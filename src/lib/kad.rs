use std::collections::VecDeque;
use std::marker::Copy;
use array_init::array_init;

pub struct Kad< IpPort:Copy, Socket> {
  bucket: [VecDeque<IpPort>;256],
  socket: Socket
}

impl <IpPort:Copy,Socket> Kad<IpPort,Socket> {
  pub fn new(socket:Socket) -> Kad<IpPort,Socket>{
    Kad{
      socket,
      bucket: array_init(|_|VecDeque::new())
    }
  }
  pub fn add(&self, key:&[u8], ip_port:IpPort){

  } 
}
