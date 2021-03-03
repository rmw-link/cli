use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn _duration() -> Duration {
  SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

pub fn sec() -> u64 {
  _duration().as_secs()
}
pub fn milli() -> u64 {
  _duration().as_millis() as u64
}
