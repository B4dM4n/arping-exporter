#![warn(
  missing_debug_implementations,
  rust_2018_idioms,
  clippy::pedantic,
  clippy::nursery
)]

mod args;
mod arp;
mod raw_socket;
mod util;

use std::{
  collections::{hash_map::Entry, HashMap},
  future::IntoFuture,
  io,
  net::{IpAddr, Ipv4Addr, SocketAddr},
  os::fd::FromRawFd as _,
  pin::pin,
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::bail;
use args::AuthCredentials;
use axum::{
  extract::{ConnectInfo, Query},
  http::{header, Request, StatusCode},
  response::{IntoResponse as _, Response},
};
use password_auth::VerifyError;
use prometheus::{Encoder, HistogramVec, IntCounterVec, IntGauge, Registry};
use serde::Deserialize;
use tokio::{sync::Mutex, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace, warn, Instrument as _, Level};
use util::{Auth, AuthRejection, LLIpv4Addr, MaxWidth};

const SECOND: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  setup_tracing()?;

  let args = <args::Args as clap::Parser>::parse();

  if args.print_buckets {
    println!("{:?}", args.metrics.exponential_buckets().unwrap());
    return Ok(());
  }

  let registry = Registry::new();
  let Metrics {
    ping_targets,
    ping_dynamic_targets,
    ping_errors,
    ping_rtt,
    ping_timeouts,
    send_timeout,
  } = setup_metrics(&registry, &args.metrics)?;

  let cancellation = CancellationToken::new();
  let arp_interfaces = Arc::new(arp::Interfaces::new(cancellation.child_token()));
  let target_send_args = Arc::new(TargetSendArgs {
    send_interval: args.send_interval.into(),
    send_timeout,
    ping_errors,
    ping_rtt,
    ping_timeouts,
  });

  let targets = TargetMap::new(
    ping_targets,
    ping_dynamic_targets,
    arp_interfaces,
    args.targets_max,
    args.dynamic_targets_hold.into(),
    target_send_args.clone(),
    cancellation.clone(),
  );
  targets
    .add(
      args
        .targets
        .into_iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()?,
      true,
    )
    .await;
  tokio::spawn(targets.clone().cleanup_task());

  let app = Arc::new(App::new(
    registry,
    args.dynamic_targets.then(|| targets.clone()),
    args.auth_credentials,
  ));
  let mut app = pin!(app.run(
    cancellation.child_token(),
    args.web_telemetry_path,
    args.web_listen_address,
    args.web_systemd_socket
  ));
  let mut shutdown_signal = pin!(shutdown_signal());

  debug!("Waiting for shutdown signal");
  #[allow(clippy::redundant_pub_crate)]
  {
    tokio::select! {
      _ = &mut app => {}
      () = &mut shutdown_signal => {}
    };
  }

  cancellation.cancel();
  let _ = app.await;
  let targets = std::mem::take(&mut *targets.targets.lock().await);
  for (hostname, TargetHandle { join_send, .. }) in targets {
    if let Err(e) = join_send.await {
      warn!("The `send` task for `{}` failed: {:?}", hostname, e);
    }
  }

  Ok(())
}

fn setup_tracing() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy(),
    )
    .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
    .try_init()
    .map_err(|e| anyhow::anyhow!(e))?;

  Ok(())
}

async fn shutdown_signal() {
  use tokio::signal;

  let ctrl_c = async {
    signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    signal::unix::signal(signal::unix::SignalKind::terminate())
      .expect("failed to install signal handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  #[allow(clippy::redundant_pub_crate)]
  {
    tokio::select! {
      () = ctrl_c => {debug!("Ctrl-C received");},
      () = terminate => {debug!("SIGTERM received");},
    }
  }
}

struct Metrics {
  ping_targets: IntGauge,
  ping_dynamic_targets: IntGauge,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
  ping_timeouts: IntCounterVec,
  send_timeout: Duration,
}

fn setup_metrics(registry: &Registry, args: &args::Metrics) -> anyhow::Result<Metrics> {
  registry.register(Box::new(
    prometheus::process_collector::ProcessCollector::for_self(),
  ))?;

  let ping_targets = prometheus::register_int_gauge_with_registry!(
    "ping_targets",
    "Number of currently active targets",
    registry
  )?;
  let ping_dynamic_targets = prometheus::register_int_gauge_with_registry!(
    "ping_dynamic_targets",
    "Number of currently active dynamic targets",
    registry
  )?;

  let rtt_buckets = args.exponential_buckets()?;
  let send_timeout = Duration::from_secs_f64(*rtt_buckets.last().unwrap());
  let ping_rtt = prometheus::register_histogram_vec_with_registry!(
    "ping_rtt",
    "Round Trip Time of the packets send to the targets",
    &["target", "version"],
    rtt_buckets,
    registry
  )?;
  let ping_timeouts = prometheus::register_int_counter_vec_with_registry!(
    "ping_timeouts",
    "Number of packets for which no answer was received in the maxium bucket time",
    &["target", "version"],
    registry
  )?;
  let ping_errors = prometheus::register_int_counter_vec_with_registry!(
    "ping_errors",
    "Number of packets failed to send or receive due to errors",
    &["target", "version"],
    registry
  )?;

  Ok(Metrics {
    ping_targets,
    ping_dynamic_targets,
    ping_errors,
    ping_rtt,
    ping_timeouts,
    send_timeout,
  })
}

struct App {
  registry: Registry,
  dynamic_targets: Option<Arc<TargetMap>>,
  auth_credentials: Option<AuthCredentials>,
}

impl App {
  const fn new(
    registry: Registry,
    dynamic_targets: Option<Arc<TargetMap>>,
    auth_credentials: Option<AuthCredentials>,
  ) -> Self {
    Self {
      registry,
      dynamic_targets,
      auth_credentials,
    }
  }

  #[tracing::instrument(ret, err, skip(self, cancellation))]
  async fn run(
    self: Arc<Self>,
    cancellation: CancellationToken,
    mut web_telemetry_path: String,
    web_listen_addresses: Vec<String>,
    web_systemd_socket: bool,
  ) -> anyhow::Result<()> {
    use axum::{routing::get, Router};

    if !web_telemetry_path.starts_with('/') {
      web_telemetry_path.insert(0, '/');
    }

    let mut router = Router::new();
    if web_telemetry_path != "/" {
      router = router.route("/", get(|| async { "" }));
    }

    let router = router
      .route(
        &web_telemetry_path,
        get({
          let this = self.clone();
          move |args, auth| this.metrics_get(args, auth)
        }),
      )
      .layer(
        TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
          let client = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ConnectInfo(addr)| {
              addr.ip()
            });
          tracing::span!(
              Level::INFO,
              "request",
              %client,
              method = %request.method(),
              uri = %MaxWidth(60, request.uri()),
              version = ?request.version(),
          )
        }),
      );

    let listeners = if web_systemd_socket {
      sd_notify::listen_fds()?
        .map(|fd| unsafe { std::net::TcpListener::from_raw_fd(fd) })
        .map(tokio::net::TcpListener::from_std)
        .collect::<Result<Vec<_>, io::Error>>()?
    } else {
      futures_util::future::join_all(
        web_listen_addresses
          .into_iter()
          .map(tokio::net::TcpListener::bind),
      )
      .await
      .into_iter()
      .collect::<Result<Vec<_>, io::Error>>()?
    };
    if listeners.is_empty() {
      bail!(
        "No listening socket configured{}",
        if web_systemd_socket {
          ". Systemd service was not activated by a socket unit"
        } else {
          ""
        }
      );
    }

    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;

    let handles = listeners
      .into_iter()
      .map(|listener| {
        let app = router.clone();
        let cancellation = cancellation.clone();

        tokio::spawn(
          async move {
            axum::serve(
              listener,
              app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .into_future()
            .await
          }
          .in_current_span(),
        )
      })
      .collect::<Vec<_>>();

    // Wait for the first task to finish
    let (res, _idx, handles) = futures_util::future::select_all(handles).await;
    // Cancel all other listener tasks and wait for them to complete
    cancellation.cancel();
    if let Err(_e) = timeout(
      Duration::from_secs(5),
      futures_util::future::join_all(handles),
    )
    .await
    {
      error!("Timeout while waiting for all lsitener tasks to finish");
    };

    // Return the potential error of the first finished task
    Ok(res??)
  }

  async fn metrics_get(
    self: Arc<Self>,
    args: Query<MetricsGetArgs>,
    auth: Result<Auth, AuthRejection>,
  ) -> Response {
    if let Some(auth_credentials) = self.auth_credentials.as_ref() {
      match auth {
        Ok(Auth::Basic(basic)) => {
          let Some(hash) = auth_credentials.basic.get(&basic.0) else {
            return (
              StatusCode::UNAUTHORIZED,
              VerifyError::PasswordInvalid.to_string(),
            )
              .into_response();
          };

          if let Err(e) = util::verify_password(basic.1.as_deref().unwrap_or_default(), hash) {
            return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
          }
        }

        Ok(Auth::Bearer(bearer)) => {
          if !auth_credentials.bearer.contains(&bearer.0) {
            return (StatusCode::UNAUTHORIZED, "Invalid access token").into_response();
          };
        }

        Err(e) => return e.into_response(),
      }
    }

    if let Some((dynamic_targets, new_targets)) = self.dynamic_targets.as_ref().zip(args.0.targets)
    {
      fn parse(s: &str) -> Option<LLIpv4Addr> {
        s.trim().parse().ok()
      }

      dynamic_targets
        .add(
          new_targets.split(',').map(str::trim).filter_map(parse),
          false,
        )
        .await;
    }

    // TODO: support prometheus::ProtobufEncoder
    let mut buffer = Vec::with_capacity(4096);
    let encoder = prometheus::TextEncoder::new();
    let metric_families = self.registry.gather();
    if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
      return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    ([(header::CONTENT_TYPE, prometheus::TEXT_FORMAT)], buffer).into_response()
  }
}

#[derive(Debug, Deserialize)]
struct MetricsGetArgs {
  targets: Option<String>,
}

struct TargetMap {
  ping_targets: IntGauge,
  ping_dynamic_targets: IntGauge,

  arp_interfaces: Arc<arp::Interfaces>,
  targets: Mutex<HashMap<LLIpv4Addr, TargetHandle>>,
  limit: usize,
  dynamic_hold_time: Duration,
  send_args: Arc<TargetSendArgs>,
  cancellation: CancellationToken,
}

impl TargetMap {
  fn new(
    ping_targets: IntGauge,
    ping_dynamic_targets: IntGauge,
    arp_interfaces: Arc<arp::Interfaces>,
    limit: usize,
    dynamic_hold_time: Duration,
    send_args: Arc<TargetSendArgs>,
    cancellation: CancellationToken,
  ) -> Arc<Self> {
    Arc::new(Self {
      ping_targets,
      ping_dynamic_targets,

      arp_interfaces,
      targets: Mutex::default(),
      limit,
      dynamic_hold_time,
      send_args,
      cancellation,
    })
  }

  #[allow(clippy::future_not_send, clippy::significant_drop_tightening)]
  #[tracing::instrument(skip(self, new_targets))]
  async fn add(&self, new_targets: impl IntoIterator<Item = LLIpv4Addr>, permanent: bool) {
    let mut targets = self.targets.lock().await;
    let now = Instant::now();

    for new in new_targets {
      let len = targets.len();
      let target = targets.entry(new).and_modify(|t| {
        if permanent && !t.permanent {
          // Remove previously dynamic target
          self.ping_dynamic_targets.dec();
        }
        t.permanent |= permanent;
        t.last_seen = now;
      });

      if let Entry::Vacant(v) = target {
        if len >= self.limit {
          continue;
        }

        self.ping_targets.inc();
        if !permanent {
          self.ping_dynamic_targets.inc();
        }

        let lladdress = v.key().to_owned();
        let arp_interface = match self.arp_interfaces.get(&lladdress.interface).await {
          Ok(arp_interface) => arp_interface,
          Err(e) => {
            warn!(%lladdress, ?e, "unable to create ARP interface");
            continue;
          }
        };

        info!(?lladdress, "new target");
        let cancellation = self.cancellation.child_token();
        let target = Arc::new(Target::new(lladdress, cancellation.clone(), arp_interface));
        let join_send = tokio::spawn(target.clone().send_loop(self.send_args.clone()));

        v.insert(TargetHandle {
          permanent,
          last_seen: now,
          cancellation,
          join_send,
        });
      }
    }
  }

  async fn cleanup(&self, now: Instant) {
    let mut targets = self.targets.lock().await;

    targets.retain(|hostname, target| {
      let retain =
        target.permanent || now.duration_since(target.last_seen) <= self.dynamic_hold_time;
      if !retain {
        debug!(%hostname, "drop target");
        target.cancellation.cancel();
        self.ping_dynamic_targets.dec();
      }
      retain
    });
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self))]
  async fn cleanup_task(self: Arc<Self>) {
    let mut cancelled = pin!(self.cancellation.cancelled());
    let mut interval = tokio::time::interval(SECOND.max(self.dynamic_hold_time / 2));

    #[allow(clippy::redundant_pub_crate)]
    loop {
      trace!("loop");
      tokio::select! {
        () = &mut cancelled => {
          break;
        }
        now = interval.tick() => {
          self.cleanup(now.into()).await;
        }
      }
    }
  }
}

#[derive(Debug)]
struct TargetHandle {
  permanent: bool,
  last_seen: Instant,
  cancellation: CancellationToken,
  join_send: JoinHandle<()>,
}

struct TargetSendArgs {
  send_interval: Duration,
  send_timeout: Duration,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
  ping_timeouts: IntCounterVec,
}

#[derive(Debug)]
struct Target {
  lladdress: LLIpv4Addr,
  cancellation: CancellationToken,
  arp_interface: Arc<arp::Interface>,
}

#[derive(Debug)]
enum PingResult {
  Success(Duration),
  Timeout,
  Error,
}

impl Target {
  fn new(
    lladdress: LLIpv4Addr,
    cancellation: CancellationToken,
    arp_interface: Arc<arp::Interface>,
  ) -> Self {
    Self {
      lladdress,
      cancellation,
      arp_interface,
    }
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, args), fields(lladdress = %self.lladdress))]
  async fn send_loop(self: Arc<Self>, args: Arc<TargetSendArgs>) {
    let mut interval = tokio::time::interval(args.send_interval);
    let lladdress = self.lladdress.to_string();

    loop {
      #[allow(clippy::redundant_pub_crate)]
      {
        tokio::select! {
          _ = interval.tick() => (),
          () = self.cancellation.cancelled() => {
            break;
          }
        }
      };

      trace!("loop");

      let this = self.clone();
      let args = args.clone();
      let lladdress = lladdress.clone();

      tokio::spawn(
        async move {
          let now = Instant::now();
          match this.send(args.send_timeout, now).await {
            PingResult::Success(rtt) => {
              args
                .ping_rtt
                .with_label_values(&[&lladdress, "arp"])
                .observe(rtt.as_secs_f64());
            }
            PingResult::Timeout => {
              args
                .ping_rtt
                .with_label_values(&[&lladdress, "arp"])
                .observe(f64::INFINITY);
              args
                .ping_timeouts
                .with_label_values(&[&lladdress, "arp"])
                .inc();
            }
            PingResult::Error => {
              args
                .ping_errors
                .with_label_values(&[&lladdress, "arp"])
                .inc();
            }
          }
        }
        .in_current_span(),
      );
    }

    let values = &[&lladdress, "arp"];
    let _ = args.ping_rtt.remove_label_values(values);
    let _ = args.ping_rtt.remove_label_values(values);
    let _ = args.ping_errors.remove_label_values(values);
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, send_timeout, now))]
  async fn send(&self, send_timeout: Duration, now: Instant) -> PingResult {
    match timeout(
      send_timeout,
      self
        .arp_interface
        .send(self.lladdress.address, now + send_timeout),
    )
    .await
    {
      Ok(Ok(Some(resp_time))) => PingResult::Success(resp_time.duration_since(now)),
      Ok(Ok(None)) | Err(_) => PingResult::Timeout,
      Ok(Err(_e)) => PingResult::Error,
    }
  }
}
