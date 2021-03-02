use crate::var::ed25519::ED25519;
use array_init::array_init;
use std::collections::VecDeque;
use std::marker::Copy;

pub struct Kad<IpPort: Copy, Socket> {
  bucket: [VecDeque<IpPort>; 256],
  socket: Socket,
}

fn comm_bit_prefix(x: &[u8], y: &[u8]) -> u32 {
  let mut n = 0;
  for (a, b) in x.iter().zip(y) {
    let t = (*a ^ *b).count_zeros();
    n += t;
    if t != 8 {
      break;
    }
  }
  n
}

impl<IpPort: Copy, Socket> Kad<IpPort, Socket> {
  pub fn new(socket: Socket) -> Kad<IpPort, Socket> {
    Kad {
      socket,
      bucket: array_init(|_| VecDeque::new()),
    }
  }
  pub fn add(&self, pk: &[u8], ip_port: IpPort) {
    // todo 测试是否是公网IP
    println!(
      "comm_bit_prefix {:?}",
      comm_bit_prefix(&b"1230"[..], &b"1232"[..])
    );
    println!("comm_bit_prefix {:?}", comm_bit_prefix(pk, pk));
    println!(
      "comm_bit_prefix {:?}",
      comm_bit_prefix(pk, ED25519.public.as_bytes())
    );
  }
}
