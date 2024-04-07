
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::SocketAddrV6;

use std::sync::Arc;

use std::io::Cursor;
use std::os::fd::AsRawFd;

use byteorder::{BigEndian, ReadBytesExt};
use parking_lot::RwLock;

use sha2::Sha256;
use hmac::{Hmac, Mac};
use serde::{Serialize, Deserialize};
use chrono::prelude::*;

use std::convert::Infallible;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;

use serde_json::json;

use unbounded_udp::Unbounded;
use unbounded_udp::Domain;


// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

mod base64 {
  use serde::Deserialize;
  use serde::Deserializer;

  use base64::prelude::*;

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
      let base64 = String::deserialize(d)?;
      BASE64_STANDARD.decode(base64.as_bytes())
        .map_err(|e| serde::de::Error::custom(e))
  }
}

/// Configuration for the pakezmatter daemon.
#[derive(Deserialize, Clone, Debug)]
struct Config {
  #[serde(default = "Config::default_listen_address")]
  listen_address: SocketAddr,

  #[allow(unused)]
  bind_interface: Option<String>,

  #[serde(default = "Config::default_api_listen_address")]
  api_listen_address: SocketAddr,

  #[serde(with = "base64")]
  shared_secret: Vec<u8>,

  peers: HashMap<String, PeerConfig>,
}

/// Configuration for a single peer.
#[derive(Deserialize, Clone, Debug)]
struct PeerConfig {
  address: SocketAddr,
}

impl Config {
  fn default_listen_address() -> SocketAddr {
    SocketAddr::new("::".parse().unwrap(), 6416)
  }

  fn default_api_listen_address() -> SocketAddr {
    SocketAddr::new("::".parse().unwrap(), 6464)
  }

  async fn load(config_path: &str) -> Result<Config, anyhow::Error> {
    let config_str = tokio::fs::read_to_string(config_path).await?;
    let config = toml::from_str(&config_str)?;

    Ok(config)
  }

  fn get_addr_map(&self) -> HashMap<SocketAddr, String> {
    self.peers.iter().map(|(k, v)| (SocketAddr::V6(socket_addr_to_v6(&v.address)), k.to_owned())).collect()
  }
}

fn get_unix_time_in_millis() -> i64 {
  Utc::now().timestamp_millis()
}

struct Packet<'a> {
  signature: &'a [u8],
  payload: &'a [u8],
}

const ERROR_TOO_SHORT: &'static str = "Too short to be a valid packet.";
const ERROR_INVALID_SIGNATURE: &'static str = "Invalid signature.";

impl Packet<'_> {
  fn new<'a>(signature: &'a [u8], payload: &'a [u8]) -> Packet<'a> {
    Packet { signature, payload }
  }

  fn generate_signature(shared_secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(shared_secret)
      .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut signature = [0; 32];
    signature.copy_from_slice(&result);
    signature
  }

  fn parse<'a>(shared_secret: &[u8], data: &'a [u8]) -> Result<Packet<'a>, &'static str> {
    if data.len() < 32 {
      return Err(ERROR_TOO_SHORT);
    }

    let (signature, payload) = data.split_at(32);

    let mut mac = HmacSha256::new_from_slice(shared_secret)
      .expect("HMAC can take key of any size");
    mac.update(payload);

    if mac.verify_slice(signature).is_err() {
      return Err(ERROR_INVALID_SIGNATURE);
    }

    Ok(Packet { signature, payload })
  }

  fn command(&self) -> Result<Command, &'static str> {
    Command::try_from(self.payload)
  }

  fn as_bytes(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(self.signature);
    buf.extend_from_slice(self.payload);
    buf
  }
}

/// 1 hour statistics for a peer measured every minute.
#[derive(Debug, Clone)]
struct PeerStatistics {
  minute_stats: Vec<u64>,
  hour_stats: Vec<MinuteStatistics>,
}

#[derive(Debug, Clone, Serialize)]
struct MinuteStatistics {
  timestamp: i64,
  count: u32,
  average_delay: f64,
}

impl PeerStatistics {
  fn new() -> PeerStatistics {
    PeerStatistics {
      minute_stats: Vec::new(),
      hour_stats: Vec::new(),
    }
  }

  fn sum_minute_stats(&mut self) {
    let sum: u64 = self.minute_stats.iter().sum();
    let count = self.minute_stats.len() as u32;
    let average = sum as f64 / count as f64;

    let timestamp = get_unix_time_in_millis();
    self.hour_stats.push(MinuteStatistics {
      timestamp,
      count,
      average_delay: average,
    });

    if self.hour_stats.len() > 60 {
      self.hour_stats.remove(0);
    }

    self.minute_stats.clear();
  }

  fn add_ping(&mut self, delay: u64) {
    self.minute_stats.push(delay);
  }
}

#[derive(Debug, Clone)]
enum Command {
  Ping {
    timestamp: i64,
  },
  Pong {
    timestamp: i64, // copied from the ping
  },
}

impl TryFrom<&[u8]> for Command {
  type Error = &'static str;

  fn try_from(data: &[u8]) -> Result<Command, &'static str> {
    let mut reader = Cursor::new(data);

    let command = reader.read_u8().map_err(|_| "Failed to read command")?;
    match command {
      0 => {
        let timestamp = reader.read_i64::<BigEndian>().map_err(|_| "Failed to read timestamp")?;
        Ok(Command::Ping { timestamp })
      }
      1 => {
        let timestamp = reader.read_i64::<BigEndian>().map_err(|_| "Failed to read timestamp")?;
        Ok(Command::Pong { timestamp })
      }
      _ => Err("Unknown command"),
    }
  }
}

fn socket_addr_to_v6(addr: &SocketAddr) -> SocketAddrV6 {
  match addr {
    SocketAddr::V4(v4) => {
      let port = v4.port();
      let v6 = v4.ip().to_ipv6_mapped();
      eprintln!("Mapped: {:?}, port: {:?}", &v6, port);
      SocketAddrV6::new(v6, port, 0, 0)
    }
    SocketAddr::V6(v6) => v6.clone(),
  }
}

#[cfg(target_os = "linux")]
fn bind_afterward(socket: &tokio::net::UdpSocket, address: &SocketAddr) -> Result<(), std::io::Error> {
  let address = socket_addr_to_v6(address);
  let addr_bytes = address.ip().octets();
  let socket_fd = socket.as_raw_fd();
  let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
  addr.sin6_family = libc::AF_INET6 as u16;
  addr.sin6_port = address.port().to_be();
  addr.sin6_flowinfo = 0;
  addr.sin6_addr = libc::in6_addr {
    s6_addr: addr_bytes,
  };
  addr.sin6_scope_id = 0;

  let addr_len = std::mem::size_of_val(&addr) as u32;
  unsafe {
    if libc::bind(socket_fd, &addr as *const libc::sockaddr_in6 as *const libc::sockaddr, addr_len) < 0 {
      return Err(std::io::Error::last_os_error());
    }
    Ok(())
  }
}

#[cfg(target_os = "macos")]
fn bind_afterward(socket: &tokio::net::UdpSocket, address: &SocketAddr) -> Result<(), std::io::Error> {
  let address = socket_addr_to_v6(address);
  let addr_bytes = address.ip().octets();
  let socket_fd = socket.as_raw_fd();
  let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
  addr.sin6_family = libc::AF_INET6 as u8;
  addr.sin6_port = address.port().to_be();
  addr.sin6_flowinfo = 0;
  addr.sin6_addr = libc::in6_addr {
    s6_addr: addr_bytes,
  };
  addr.sin6_scope_id = 0;

  let addr_len = std::mem::size_of_val(&addr) as u32;
  unsafe {
    if libc::bind(socket_fd, &addr as *const libc::sockaddr_in6 as *const libc::sockaddr, addr_len) < 0 {
      return Err(std::io::Error::last_os_error());
    }
    Ok(())
  }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
  let config_path = std::env::args().nth(1).unwrap_or("/etc/pakezmatter.toml".to_string());
  let config = Arc::new(Config::load(&config_path).await?);
  let addr_map = Arc::new(config.get_addr_map());
  eprintln!("Address map: {:?}", &addr_map);
  // eprintln!("Config: {:?}", &config);

  let socket = std::net::UdpSocket::unbounded(Domain::Ipv6)?;
  socket.set_nonblocking(true)?;

  let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);

  #[cfg(target_os = "linux")]
  {
    if let Some(interface) = &config.bind_interface {
      let interface = interface.as_bytes();
      let _ = socket.bind_device(Some(interface));
    }
  }

  bind_afterward(&socket, &config.listen_address)?;

  let socket_send = socket.clone();
  let config_send = config.clone();
  let addr_map_send = addr_map.clone();

  let peer_stats = RwLock::new(HashMap::new());
  let peer_stats = Arc::new(peer_stats);
  for peer_name in config.peers.keys() {
    peer_stats.write().insert(peer_name.clone(), PeerStatistics::new());
  }

  let addr_map_receive = addr_map.clone();
  let peer_stats_receive = peer_stats.clone();
  let config_receive = config.clone();

  tokio::spawn(async move {
    let config = config_receive;
    let addr_map = addr_map_receive;
    let peer_stats = peer_stats_receive;
    let mut buf = [0; 1024];
    loop {
      let (len, addr) = if let Ok(v) = socket.recv_from(&mut buf).await {
        v
      } else {
        continue;
      };
      let packet = Packet::parse(&config.shared_secret, &buf[..len]);

      match packet {
        Ok(packet) => {
          if let Ok(command) = packet.command() {
            match command {
              Command::Ping { timestamp } => {
                let mut response = Vec::new();
                response.push(1);
                response.extend_from_slice(&timestamp.to_be_bytes());
                let signature = Packet::generate_signature(&config.shared_secret, &response);
                let packet = Packet::new(&signature, &response);
                let payload = packet.as_bytes();
                let _ = socket.send_to(&payload, addr).await;
              }
              Command::Pong { timestamp } => {
                let peer_name = addr_map.get(&addr);
                let peer_name = if let Some(peer_name) = peer_name {
                  peer_name
                } else {
                  eprintln!("Unknown peer: {}", addr);
                  continue;
                };
                let mut peer_stats = peer_stats.write();
                let peer_stats = peer_stats.get_mut(peer_name).unwrap();
                peer_stats.add_ping((get_unix_time_in_millis() - timestamp).try_into().unwrap());
              }
            }
          }
        }
        Err(e) => {
          eprintln!("Error: {}", e);
        }
      }
    }
  });

  tokio::spawn(async move {
    let addr_map = addr_map_send;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
      interval.tick().await;

      for (addr, _) in addr_map.iter() {
        let addr = SocketAddr::V6(socket_addr_to_v6(addr));
        let timestamp = get_unix_time_in_millis();
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(&timestamp.to_be_bytes());
        let signature = Packet::generate_signature(&config_send.shared_secret, &buf);
        let packet = Packet::new(&signature, &buf);
        let payload = packet.as_bytes();
        let _ = socket_send.send_to(&payload, addr).await;
      }
    }
  });

  let peer_stats_summing = peer_stats.clone();
  tokio::spawn(async move {
    let mut interval = tokio::time::interval_at(
      (std::time::Instant::now() + std::time::Duration::from_millis(500)).into(),
      std::time::Duration::from_secs(60));
    loop {
      interval.tick().await;

      let mut peer_stats = peer_stats_summing.write();
      for (_, stats) in peer_stats.iter_mut() {
        stats.sum_minute_stats();
      }
    }
  });

  let http_listener = TcpListener::bind(config.api_listen_address).await?;
  loop {
    let (stream, _) = http_listener.accept().await?;
    let peer_stats = peer_stats.clone();
    let io = TokioIo::new(stream);

    tokio::spawn(async move {
      let service = service_fn(move |req: Request<_>| {
        let peer_stats = peer_stats.clone();
        async move {
          match req.uri().path() {
            "/api/v1/stats" => {
              let peer_stats = peer_stats.read();
              let mut response = json!({});
              for (peer_name, stats) in peer_stats.iter() {
                let hour_stats = stats.hour_stats.clone();
                response[peer_name] = serde_json::to_value(&hour_stats).unwrap();
              }
              Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(serde_json::to_string(&response).unwrap()))))
            }
            _ => Ok(Response::builder().status(404).body(Full::new(Bytes::from(""))).unwrap()),
          }
        }
      });

      if let Err(e) = http1::Builder::new()
        .serve_connection(io, service)
        .await
      {
        eprintln!("Error: {}", e);
      }
    });
  }
}
