use std::net::UdpSocket;

/// get the local ip address, return an `Option<String>`. when it fail, return `None`.
pub fn local_ip() -> Option<String> {
  let socket = match UdpSocket::bind("0.0.0.0:0") {
    Ok(s) => s,
    Err(_) => return None,
  };

  match socket.connect("119.29.29.29:53") {
    Ok(()) => (),
    Err(_) => return None,
  };

  match socket.local_addr() {
    Ok(addr) => return Some(addr.ip().to_string()),
    Err(_) => return None,
  };
}
