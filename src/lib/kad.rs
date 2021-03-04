use crate::lib::now::milli;
use crate::var::ed25519::ED25519;
use array_init::array_init;
use skiplist::SkipMap;
use std::cmp::Ord;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::marker::Copy;

#[derive(Debug)]
pub struct AddrPk<Addr> {
  addr: Addr,
  pk: [u8; 32],
}

#[derive(Debug)]
pub struct AddrId {
  alive_id: u64,
  send_id: u64,
}

pub struct Kad<'a, Addr: Debug + Ord + Copy, Socket> {
  bucket: [VecDeque<AddrPk<Addr>>; 257],
  socket: &'a Socket,
  alive: SkipMap<u64, Addr>,
  send: SkipMap<u64, Addr>,
  addr_id: BTreeMap<Addr, AddrId>,
  _id: u64,
}

const TIMEOUT: usize = 60;

pub fn comm_bit_prefix<const N: usize>(x: &[u8; N], y: &[u8; N]) -> usize {
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

impl<'a, Addr: Debug + Ord + PartialEq + Copy, Socket> Kad<'a, Addr, Socket> {
  pub fn new(socket: &Socket) -> Kad<Addr, Socket> {
    Kad {
      socket,
      bucket: array_init(|_| VecDeque::new()),
      alive: SkipMap::<u64, Addr>::new(),
      send: SkipMap::<u64, Addr>::new(),
      addr_id: BTreeMap::<Addr, AddrId>::new(),
      _id: 0,
    }
  }

  fn id(&mut self) -> u64 {
    let mut now = (milli() - *BEGIN_MILLI) * 16;
    if now <= self._id {
      now = self._id;
    }
    self._id = now;
    now
  }

  pub fn ping(&mut self) {
    let now = self.id();
    let skipmap = &mut self.alive;
  }

  pub fn add(&mut self, pk: [u8; 32], addr: Addr) {
    if self.addr_id.contains_key(&addr) {
      return;
    }
    let id = self.id();
    self.addr_id.insert(
      addr,
      AddrId {
        alive_id: id,
        send_id: id,
      },
    );
    self.alive.insert(id, addr);
    self.send.insert(id, addr);
    let n = comm_bit_prefix(&pk, &ED25519.public.as_bytes());
    self.bucket[n].push_back(AddrPk { addr, pk });
    println!("send {:?}", self.alive);
    println!("alive {:?}", self.send);
    println!("bucket {:?}", self.bucket);
    println!("addr_id {:?}", self.addr_id);
  }
}
