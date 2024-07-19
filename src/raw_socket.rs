use std::{
  io::{IoSlice, Result as IoResult},
  mem::MaybeUninit,
  ptr,
};

use socket2::{SockAddr, Socket};
use tokio::io::unix::AsyncFd;

#[derive(Debug)]
pub struct RawSocket {
  io: AsyncFd<Socket>,
}

#[allow(dead_code)]
impl RawSocket {
  pub fn new(socket: Socket) -> IoResult<Self> {
    let io = AsyncFd::new(socket)?;
    Ok(Self { io })
  }

  pub async fn send(&self, buf: &[u8]) -> IoResult<usize> {
    self.write(|s| s.send(buf)).await
  }

  pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
    self.write(|s| s.send_vectored(bufs)).await
  }

  pub async fn send_to(&self, buf: &[u8], addr: &SockAddr) -> IoResult<usize> {
    self.write(|s| s.send_to(buf, addr)).await
  }

  pub async fn recv(&self, buf: &mut [u8]) -> IoResult<usize> {
    let buf = unsafe { &mut *(ptr::from_mut(buf) as *mut [MaybeUninit<u8>]) };
    self.read(move |s| s.recv(buf)).await
  }

  pub async fn recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SockAddr)> {
    let buf = unsafe { &mut *(ptr::from_mut(buf) as *mut [MaybeUninit<u8>]) };
    self.read(move |s| s.recv_from(buf)).await
  }

  #[allow(clippy::future_not_send)]
  async fn read<F: FnMut(&Socket) -> IoResult<R>, R>(&self, mut f: F) -> IoResult<R> {
    loop {
      let mut guard = self.io.readable().await?;
      match guard.try_io(|inner| f(inner.get_ref())) {
        Ok(r) => return r,
        Err(_e) => continue,
      }
    }
  }

  #[allow(clippy::future_not_send)]
  async fn write<F: FnMut(&Socket) -> IoResult<R>, R>(&self, mut f: F) -> IoResult<R> {
    loop {
      let mut guard = self.io.writable().await?;
      match guard.try_io(|inner| f(inner.get_ref())) {
        Ok(r) => return r,
        Err(_e) => continue,
      }
    }
  }
}
