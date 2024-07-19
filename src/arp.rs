use std::{
  collections::{hash_map::Entry, HashMap},
  future::Future,
  io::{Error as IoError, Result as IoResult},
  mem::size_of,
  net::Ipv4Addr,
  sync::{Arc, Weak},
  time::{Duration, Instant},
};

use nix::{errno::Errno, libc};
use pnet::{
  packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::EtherTypes,
  },
  util::MacAddr,
};
use socket2::{Domain, Socket, Type};
use tokio::sync::{
  mpsc::{self, error::SendError},
  oneshot, Mutex,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::raw_socket::RawSocket;

const PKT_ARP_SIZE: usize = ArpPacket::minimum_packet_size();

type WaiterMap = HashMap<Ipv4Addr, Waiter>;

#[derive(Debug)]
struct Waiter {
  sender: oneshot::Sender<Option<Instant>>,
  deadline: Instant,
}

#[derive(Debug)]
pub struct Interface {
  cancellation: CancellationToken,
  sender: mpsc::Sender<Request>,
}

impl Interface {
  fn new(
    cancellation: CancellationToken,
    ifindex: i32,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
  ) -> IoResult<(Arc<Self>, impl Future<Output = ()> + Send + Sync)> {
    let socket = Socket::new_raw(Domain::PACKET, Type::DGRAM, None)?;

    // socket.bind_device(Some(b"enp4s0"))?;
    socket.set_nonblocking(true)?;

    let ((), address) = unsafe {
      #[allow(clippy::cast_possible_truncation)]
      socket2::SockAddr::try_init(|addr_storage, len| {
        // check struct size at compile time
        let _ = [(); size_of::<libc::sockaddr_storage>() - size_of::<libc::sockaddr_ll>()];

        let ptr = addr_storage.cast::<libc::sockaddr_ll>();
        *ptr = libc::sockaddr_ll {
          sll_family: libc::AF_PACKET as u16,
          sll_protocol: u16::to_be(libc::ETH_P_ARP as u16),
          sll_ifindex: ifindex,
          sll_hatype: 0,
          sll_pkttype: 0,
          sll_halen: 0,
          sll_addr: [0; 8],
        };
        *len = size_of::<libc::sockaddr_ll>() as u32;
        Ok(())
      })?
    };

    socket.bind(&address).unwrap();

    let raw_socket = RawSocket::new(socket)?;
    let (sender, receiver) = mpsc::channel(32);
    let this = Arc::new(Self {
      cancellation,
      sender,
    });
    let task = {
      let this = this.clone();
      this.task(raw_socket, receiver, ifindex, source_ip, source_mac)
    };

    Ok((this, task))
  }

  pub async fn send(
    &self,
    addr: Ipv4Addr,
    deadline: Instant,
  ) -> Result<Option<Instant>, mpsc::error::SendError<()>> {
    let (sender, receiver) = oneshot::channel();
    match self
      .sender
      .send(Request {
        target_ip: addr,
        waiter: Waiter { sender, deadline },
      })
      .await
    {
      Ok(()) => match receiver.await {
        Ok(i) => Ok(i),
        Err(_e) => Ok(None),
      },
      Err(_e) => Err(SendError(())),
    }
  }

  async fn task(
    self: Arc<Self>,
    socket: RawSocket,
    mut receiver: mpsc::Receiver<Request>,
    ifindex: i32,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
  ) {
    let mut buf = [0; PKT_ARP_SIZE];
    let mut waiters = WaiterMap::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(10));

    #[allow(clippy::redundant_pub_crate)]
    loop {
      tokio::select! {
        biased;

        () = self.cancellation.cancelled() => break,
        res = socket.recv(buf.as_mut_slice()) => {
          Self::handle_packet(&mut waiters, source_mac, buf.as_slice(), res);
        },
        req = receiver.recv() => if let Some(req) = req {
          self.handle_request(&mut waiters, &socket, ifindex, source_ip, source_mac, req).await;
        } else {
          break;
        },
        now = cleanup_interval.tick() => {
          Self::cleanup(&mut waiters, now.into_std());
        },
      };
    }
  }

  #[allow(clippy::needless_pass_by_value)]
  fn handle_packet(waiters: &mut WaiterMap, source_mac: MacAddr, buf: &[u8], res: IoResult<usize>) {
    if let Ok(len) = res {
      let buf = &buf[..len];
      if buf.len() < PKT_ARP_SIZE {
        return;
      }

      let pkt = ArpPacket::new(buf).unwrap();
      debug!(?pkt, "received packet");

      if pkt.get_hardware_type() == ArpHardwareTypes::Ethernet
        && pkt.get_protocol_type() == EtherTypes::Ipv4
        && pkt.get_hw_addr_len() == 6
        && pkt.get_proto_addr_len() == 4
        && pkt.get_operation() == ArpOperations::Reply
        && pkt.get_target_hw_addr() == source_mac
      {
        let target_addr = pkt.get_sender_proto_addr();
        let now = Instant::now();

        if let Some(waiter) = waiters.remove(&target_addr) {
          let _ = waiter.sender.send(Some(now));
        }
      }
    }
  }

  async fn handle_request(
    &self,
    waiters_map: &mut WaiterMap,
    socket: &RawSocket,
    ifindex: i32,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    Request { target_ip, waiter }: Request,
  ) {
    let prev = waiters_map.insert(target_ip, waiter);
    if let Some(waiter) = prev {
      let _ = waiter.sender.send(None);
    }

    let mut pkt_buf = [0u8; PKT_ARP_SIZE];

    {
      // Build the ARP frame on top of the ethernet frame
      let mut pkt_arp = MutableArpPacket::new(&mut pkt_buf[..]).unwrap();

      pkt_arp.set_hardware_type(ArpHardwareTypes::Ethernet);
      pkt_arp.set_protocol_type(EtherTypes::Ipv4);
      pkt_arp.set_hw_addr_len(6);
      pkt_arp.set_proto_addr_len(4);
      pkt_arp.set_operation(ArpOperations::Request);
      pkt_arp.set_sender_hw_addr(source_mac);
      pkt_arp.set_sender_proto_addr(source_ip);
      pkt_arp.set_target_hw_addr(MacAddr::broadcast());
      pkt_arp.set_target_proto_addr(target_ip);
    }

    let ((), address) = unsafe {
      #[allow(clippy::cast_possible_truncation)]
      socket2::SockAddr::try_init(|addr_storage, len| {
        // check struct size at compile time
        let _ = [(); size_of::<libc::sockaddr_storage>() - size_of::<libc::sockaddr_ll>()];

        let ptr = addr_storage.cast::<libc::sockaddr_ll>();
        *ptr = libc::sockaddr_ll {
          sll_family: libc::AF_PACKET as u16,
          sll_protocol: u16::to_be(libc::ETH_P_ARP as u16),
          sll_ifindex: ifindex,
          sll_hatype: libc::ARPHRD_ETHER,
          sll_pkttype: 0,
          sll_halen: 6,
          sll_addr: [0xFF; 8],
        };
        *len = size_of::<libc::sockaddr_ll>() as u32;
        Ok(())
      })
      .unwrap()
    };

    if let Err(e) = socket.send_to(&pkt_buf[..], &address).await {
      warn!("Unable to send ARP packet to {target_ip}: {e}");
    };
  }

  fn cleanup(waiters_map: &mut WaiterMap, now: Instant) {
    waiters_map.retain(|_idx, w| w.deadline >= now);
  }
}

struct Request {
  target_ip: Ipv4Addr,
  waiter: Waiter,
}

pub struct Interfaces {
  cancellation: CancellationToken,
  bound: Mutex<HashMap<u32, Weak<Interface>>>,
}

impl Interfaces {
  pub fn new(cancellation: CancellationToken) -> Self {
    Self {
      cancellation,
      bound: Mutex::default(),
    }
  }

  #[allow(clippy::significant_drop_tightening)]
  pub async fn get(&self, name: &str) -> IoResult<Arc<Interface>> {
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr().cast()) };
    if ifindex == 0 {
      return Err(IoError::from_raw_os_error(Errno::last_raw()));
    }

    let mut guard = self.bound.lock().await;
    let entry = guard.entry(ifindex);

    Ok(match entry {
      Entry::Occupied(mut e) => {
        if let Some(interface) = e.get().upgrade() {
          interface
        } else {
          let interface = self.create_interface(ifindex)?;
          e.insert(Arc::downgrade(&interface));
          interface
        }
      }
      Entry::Vacant(e) => {
        let interface = self.create_interface(ifindex)?;
        e.insert(Arc::downgrade(&interface));
        interface
      }
    })
  }

  fn create_interface(&self, ifindex: u32) -> IoResult<Arc<Interface>> {
    let iface = pnet::datalink::interfaces()
      .into_iter()
      .find(|i| i.index == ifindex)
      .ok_or_else(|| IoError::other("ifindex not found"))?;

    let source_ip = iface
      .ips
      .iter()
      .find_map(|ip| match ip {
        pnet::ipnetwork::IpNetwork::V4(a) => Some(a.ip()),
        pnet::ipnetwork::IpNetwork::V6(_) => None,
      })
      .ok_or_else(|| IoError::other("no source_ip found for interface"))?;
    let source_mac = iface
      .mac
      .ok_or_else(|| IoError::other("no mac address found for interface"))?;

    #[allow(clippy::cast_possible_wrap)]
    let (interface, task) = Interface::new(
      self.cancellation.child_token(),
      ifindex as i32,
      source_ip,
      source_mac,
    )?;
    tokio::spawn(task);

    Ok(interface)
  }
}
