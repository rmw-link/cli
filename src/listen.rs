use crate::lib::connecting::Connecting;
use crate::lib::kad::Kad;
use crate::lib::leading_zero;
use crate::lib::now::sec;
use crate::var::cmd;
use crate::var::ed25519::{ED25519, SEED};
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use async_std::stream;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek_blake2b::{PublicKey as Ed25519PublicKey, Signature, Signer, Verifier};
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Mutex;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

extern crate std;

pub const VERSION: u16 = 1;
pub const MTU: usize = 1472;
pub const TIMEOUT: u64 = 16;
pub const LEADING_ZEROS: u32 = 19;

pub trait ToBytes {
  fn to_bytes(&self) -> Bytes;
}

impl ToBytes for SocketAddr {
  fn to_bytes(&self) -> Bytes {
    let mut r = BytesMut::with_capacity(16 + 2);
    match self.ip() {
      IpAddr::V4(ip) => {
        r.put_u32(ip.into());
      }
      IpAddr::V6(ip) => {
        r.put_u128(ip.into());
      }
    }
    r.put_u16(self.port());
    r.into()
  }
}

pub async fn udp(
  socket: &UdpSocket,
  connecting: &Connecting<SocketAddrV4>,
  kad: &Mutex<Kad<'_, SocketAddrV4, UdpSocket>>,
) {
  macro_rules! send_to {
    ($val:expr, $addr:expr) => {
      Await!(socket.send_to(&$val, $addr));
    };
  }

  for addr in "47.104.79.244:30110".to_socket_addrs().unwrap() {
    match addr {
      SocketAddr::V4(addr) => {
        connecting.add(addr);
        let mut buf = BytesMut::with_capacity(17);
        buf.put_u8(cmd::ping);
        buf.put_u16(VERSION);
        buf.put_u64(sec());
        buf.put_u16(addr.port());
        buf.put_u32((*addr.ip()).into());
        send_to!(buf, addr);
      }
      SocketAddr::V6(addr) => {
        warn!("ipv6 not supported {:?}", addr);
      }
    }
  }

  let mut seed = SEED.to_vec();
  seed.extend_from_slice(machine_uid::get().unwrap().as_bytes());
  let seed_aes = blake3::hash(&seed).as_bytes().to_vec();
  let seed_seahash = blake3::hash(&seed_aes);

  let mut input = BytesMut::new();
  input.resize(MTU, 0);
  loop {
    match socket.recv_from(&mut input).await {
      Ok((n, src)) => {
        macro_rules! reply {
          ($val:expr) => {
            send_to!($val, src);
          };
        }
        macro_rules! xsk {
          () => {{
            let seed = {
              let mut t = BytesMut::with_capacity(4 + 2 + 32);
              t.put(src.to_bytes());
              t.put(&*seed_aes);
              blake3::hash(&t)
            };

            StaticSecret::from(*seed.as_bytes())
          }};
        }
        match src {
          SocketAddr::V4(src) => {
            let ip = *src.ip();
            let port = src.port();
            macro_rules! time_hash {
              ($sec:expr) => {{
                let mut t = BytesMut::with_capacity(32 + 8 + 4 + 2);
                t.put(&seed_seahash.as_bytes()[..]);
                t.put_u64($sec);
                t.put_u32(ip.into());
                t.put_u16(port.into());
                seahash::hash(&t)
              }};
            }
            if n > 0 {
              info!(
                "{} {} -> cmd {} recv {}",
                ip,
                port,
                //Ipv4Addr::from(u32::from(ip)),
                // u32::from(ip),
                input[0],
                n,
                //input.len(),
              );
              let cmd = input[0];
              let mut buf = BytesMut::from(&input[1..n]);
              match cmd {
                cmd::ping => match n {
                  1 => reply!([]),
                  17 => {
                    let version = buf.get_u16();
                    if version > VERSION {
                      warn!("TODO 升级版本")
                    }
                    let _ = buf.get_u64(); // time , ignore
                    let now = sec();
                    let token = time_hash!(now);
                    let mut t = BytesMut::with_capacity(17);
                    t.put_u8(cmd::pong);
                    t.put_u64(now);
                    t.put_u64(token);
                    reply!(t);
                  }
                  n => {
                    if n >= 145 {
                      let n = seahash::hash(&buf);
                      if n.leading_zeros() >= LEADING_ZEROS {
                        if let Ok(rxpk) = buf.split_to(32)[..].try_into() as Result<[u8; 32], _> {
                          let rxpk = PublicKey::from(rxpk);
                          let xsk = xsk!();
                          let xpk = PublicKey::from(&xsk);
                          if xpk != rxpk {
                            // 如果连接公钥是自己，放弃连接
                            let mut time_hash = buf.split_to(16);
                            let time = time_hash.get_u64();
                            let now = sec();
                            if now >= time
                              && now < (time + TIMEOUT)
                              && time_hash.get_u64() == time_hash!(time)
                            {
                              if let Ok(sign) =
                                buf.split_to(64)[..].try_into() as Result<[u8; 64], _>
                              {
                                let sign = Signature::from(sign);
                                if let Ok(epk) = Ed25519PublicKey::from_bytes(&buf.split_to(32)) {
                                  if epk.verify(&input[1..49], &sign).is_ok() {
                                    let mut pk = ED25519.public.as_bytes().to_vec();
                                    let secret = xsk.diffie_hellman(&rxpk);
                                    pk.extend(&ED25519.sign(secret.as_bytes()).to_bytes()[..]);

                                    let cipher =
                                      Aes256Gcm::new(GenericArray::from_slice(secret.as_bytes()));

                                    let nonce = thread_rng().gen::<[u8; 12]>();
                                    let nonce = GenericArray::from_slice(&nonce);

                                    if let Ok(ciphed) = cipher.encrypt(nonce, &pk[..]) {
                                      let mut b = BytesMut::with_capacity(1 + 32 + 12 + (96 + 16));
                                      b.put_u8(cmd::pong);
                                      b.put(&xpk.as_bytes()[..]);
                                      b.put(&nonce[..]);
                                      b.put(&ciphed[..]);
                                      reply!(b.split());
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                },
                cmd::pong => match n {
                  17 => {
                    if connecting.has(&src) {
                      let sk = xsk!();

                      let mut pk = PublicKey::from(&sk).as_bytes().to_vec();

                      pk.extend(buf);

                      let sign = &ED25519.sign(&pk).to_bytes()[..];
                      pk.extend(sign);
                      pk.extend(&ED25519.public.as_bytes()[..]);

                      let pk = &pk[..];

                      let mut t = BytesMut::with_capacity(1 + 32 + 8 + 8 + 64 + 32 + 8);
                      t.put_u8(cmd::ping);

                      t.put(&leading_zero::find(LEADING_ZEROS, pk, |s| seahash::hash(s))[..]);
                      reply!(t.split());
                    }
                  }
                  157 => {
                    if connecting.pop(&src) {
                      if let Ok(rxpk) = buf.split_to(32)[..].try_into() as Result<[u8; 32], _> {
                        let rxpk = PublicKey::from(rxpk);
                        let xsk = xsk!();
                        let secret = xsk.diffie_hellman(&rxpk);
                        let nonce = buf.split_to(12);
                        let nonce = GenericArray::from_slice(&nonce);
                        let cipher = Aes256Gcm::new(GenericArray::from_slice(secret.as_bytes()));
                        if let Ok(plain) = cipher.decrypt(nonce, &buf[..]) {
                          //let mut sign = ED25519.sign(secret.as_bytes()).to_bytes().to_vec();
                          //sign.extend(&xpk.as_bytes()[..]);
                          let epkb = &plain[..32];
                          if let Ok(epk) = Ed25519PublicKey::from_bytes(epkb) {
                            if let Ok(sign) = plain[32..].try_into() as Result<[u8; 64], _> {
                              let sign = Signature::from(sign);
                              if epk.verify(secret.as_bytes(), &sign).is_ok() {
                                kad.lock().unwrap().add(epkb, src);
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  _ => {}
                },
                _ => {
                  info!("TODO cmd {}", cmd);
                }
              };
            } else {
              info!("{:?} pinged alive", src);
            }
          }
          SocketAddr::V6(src) => {
            warn!("ipv6 {:?}", src)
          }
        }
      }
      Err(err) => error!("{:?}", err),
    };
  }
}

pub async fn timer(
  connecting: &Connecting<SocketAddrV4>,
  kad: &Mutex<Kad<'_, SocketAddrV4, UdpSocket>>,
) {
  let mut interval = stream::interval(Duration::from_secs(1));

  while interval.next().await.is_some() {
    connecting.clean();
    kad.lock().unwrap().alive();
  }
}

pub async fn listen(socket: UdpSocket) {
  let connecting = Connecting::<SocketAddrV4>::new(TIMEOUT);
  let kad = Mutex::new(Kad::<SocketAddrV4, UdpSocket>::new(&socket));
  let srv = udp(&socket, &connecting, &kad);
  srv.join(timer(&connecting, &kad)).await;
}
