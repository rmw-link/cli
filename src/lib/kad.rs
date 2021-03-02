use crate::var::ed25519::ED25519;
use array_init::array_init;
use std::collections::VecDeque;
use std::marker::Copy;
use std::cmp::PartialEq;
use std::fmt::Debug;

pub struct Kad<'a, Addr: Debug+PartialEq+Copy, Socket> {
  bucket: [VecDeque<Addr>; 257],
  socket: &'a Socket,
}

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

impl<'a, Addr: Debug+PartialEq+Copy, Socket> Kad<'a, Addr, Socket> {
  pub fn new(socket: &Socket) -> Kad<Addr, Socket> {
    Kad {
      socket,
      bucket: array_init(|_| VecDeque::new()),
    }
  }
  pub fn add(&mut self, pk: &[u8], addr: Addr) {
    // todo 测试是否是公网IP
    println!(
      "comm_bit_prefix {:?}",
      comm_bit_prefix(&b"1230"[..], &b"1232"[..])
    );
    println!(
      "comm_bit_prefix {:?}",
      comm_bit_prefix(&b"112"[..], &b"7232"[..])
    );
    println!("comm_bit_prefix {:?}", comm_bit_prefix(pk, pk));
    let n = comm_bit_prefix(pk, ED25519.public.as_bytes());
    println!("comm_bit_prefix {:?}", n);
    let v = &mut self.bucket[n];
    if let None = v.iter().position(|&x|x==addr) {
        v.push_back(addr);
    }
    println!("bucket {:?}",v)
  }
}
