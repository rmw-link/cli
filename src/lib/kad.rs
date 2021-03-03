use crate::lib::now::milli;
use crate::var::ed25519::ED25519;
use array_init::array_init;
use skiplist::SkipMap;
use std::cmp::PartialEq;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::marker::Copy;
use std::net::{SocketAddr, SocketAddrV4};

pub struct Kad<'a, Addr: Debug + PartialEq + Copy, Socket> {
  bucket: [VecDeque<Addr>; 257],
  socket: &'a Socket,
  alive: SkipMap<u64, &'a str>,
  send: SkipMap<u64, &'a str>,
}

const TIMEOUT: usize = 60;

pub fn comm_bit_prefix(x: &[u8], y: &[u8]) -> usize {
  let mut n: usize = 0;
  for (a, b) in x.iter().zip(y) {
    let t = (*a ^ *b).count_zeros() as usize;
    n += t;
    if t != 8 {
      break;
    }
  }
  n
}

lazy_static! {
  pub static ref BEGIN_MILLI: u64 = milli();
}

impl<'a, Addr: Debug + PartialEq + Copy, Socket> Kad<'a, Addr, Socket> {
  pub fn new(socket: &Socket) -> Kad<Addr, Socket> {
    Kad {
      socket,
      bucket: array_init(|_| VecDeque::new()),
      alive: SkipMap::<u64, &str>::new(),
      send: SkipMap::<u64, &str>::new(),
    }
  }
  pub fn alive(&mut self) {
    let skipmap = &mut self.alive;
    let now = (milli() - *BEGIN_MILLI) * 16;

    skipmap.insert(now, "");
    skipmap.insert(now + 1, "");

    println!("kad clean : {:?}", skipmap);
    println!("get {} {:?}", 1, skipmap.get(&1));
    println!("get {} {:?}", 3, skipmap.get(&3));
  }
  pub fn add(&mut self, pk: &[u8], addr: Addr) {
    // todo 测试是否是公网IP
    let n = comm_bit_prefix(pk, ED25519.public.as_bytes());
    println!("comm_bit_prefix {:?}", n);
    let v = &mut self.bucket[n];

    if let None = v.iter().position(|&x| x == addr) {
      v.push_back(addr);
    }
  }
}
