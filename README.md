# pakezmatter

Packet loss monitoring system written in Rust.

## Example Setup

/etc/pakezmatter.toml:

```toml
listen_address = "[::]:6416"
api_listen_address = "[::]:6464"
shared_secret = "Bw+vVOUVozjJzeBo1OZ6q+0YCyJt8f+v3dc7YtUyPM0="

[peers.router1]
address = "10.10.10.10:6416"
```

/srv/pakezmatter.service:

```
[Unit]
Description=Pakezmatter Server
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/
ExecStart=/usr/local/bin/pakezmatter /etc/pakezmatter.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
git clone https://github.com/menhera-org/pakezmatter.git
cd pakezmatter
cargo build --release
sudo cp target/release/pakezmatter /usr/local/bin/
sudo systemctl enable --now pakezmatter
```
