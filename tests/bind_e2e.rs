//! End-to-end coverage against a real BIND 9 process.
//!
//! Run explicitly with: `cargo test --test bind_e2e -- --ignored --nocapture`.
//! Optional executable overrides: `BIND_NAMED_BIN` and `BIND_RNDC_BIN`.

use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::time::sleep;

const TEST_ZONE: &str = "squilladns-e2e.test";
const TEST_OWNER: &str = "www.squilladns-e2e.test";
const FIRST_IP: &str = "192.0.2.81";
const SECOND_IP: &str = "192.0.2.82";
const RNDC_SECRET: &str = "c3F1aWxsYWRucy1lMmUtcm5kYy1zZWNyZXQ=";

#[test]
#[ignore = "requires named and rndc; run with --ignored"]
fn bind_dynamic_zone_lifecycle_survives_restart() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_bind_dynamic_zone_lifecycle())
        .unwrap();
}

async fn run_bind_dynamic_zone_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let work_dir = TempDirectory(temporary_directory()?);
    let work_path = work_dir.0.as_path();
    let zones_dir = work_dir.0.join("zones");
    fs::create_dir_all(&zones_dir)?;

    let dns_port = free_udp_port()?;
    let rndc_port = free_tcp_port()?;
    let api_port = free_tcp_port()?;
    let named_config = work_dir.0.join("named.conf");
    let rndc_config = work_dir.0.join("rndc.conf");
    write_bind_configs(work_path, &named_config, &rndc_config, dns_port, rndc_port)?;

    let named_bin = executable("BIND_NAMED_BIN", "named");
    let rndc_bin = executable("BIND_RNDC_BIN", "rndc");
    let mut named = ChildGuard(start_named(&named_bin, &named_config, dns_port, work_path)?);
    wait_for_named(&mut named.0, dns_port).await?;

    let api_bin = env!("CARGO_BIN_EXE_squilladns");
    let api = start_api(
        api_bin,
        api_port,
        &zones_dir,
        &rndc_bin,
        &rndc_config,
        work_path,
    )?;
    let mut api = ChildGuard(api);
    let client = Client::new();
    let base_url = format!("http://127.0.0.1:{}", api_port);
    wait_for_api(&client, &base_url, &mut api.0).await?;

    let create = client
        .put(format!("{}/zones/{}", base_url, TEST_ZONE))
        .json(&zone_payload(FIRST_IP))
        .send()
        .await?;
    assert_eq!(create.status(), StatusCode::CREATED);
    assert!(response_active(create.json::<Value>().await?));
    wait_for_a_record(dns_port, Some(FIRST_IP)).await?;

    let update = client
        .put(format!("{}/zones/{}", base_url, TEST_ZONE))
        .json(&zone_payload(SECOND_IP))
        .send()
        .await?;
    assert_eq!(update.status(), StatusCode::OK);
    assert!(response_active(update.json::<Value>().await?));
    wait_for_a_record(dns_port, Some(SECOND_IP)).await?;

    named.stop()?;
    named = ChildGuard(start_named(&named_bin, &named_config, dns_port, work_path)?);
    wait_for_named(&mut named.0, dns_port).await?;
    wait_for_a_record(dns_port, Some(SECOND_IP)).await?;

    let delete = client
        .delete(format!("{}/zones/{}", base_url, TEST_ZONE))
        .send()
        .await?;
    assert_eq!(delete.status(), StatusCode::OK);
    wait_for_a_record(dns_port, None).await?;

    api.stop()?;
    named.stop()?;
    Ok(())
}

fn zone_payload(address: &str) -> Value {
    json!({
        "records": [
            { "type": "A", "name": "www", "value": address }
        ]
    })
}

fn response_active(response: Value) -> bool {
    response.get("persisted").and_then(Value::as_bool) == Some(true)
        && response.get("active").and_then(Value::as_bool) == Some(true)
}

fn executable(variable: &str, fallback: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

fn temporary_directory() -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "squilladns-bind-e2e-{}-{}",
        std::process::id(),
        nonce
    ));
    fs::create_dir(&path)?;
    Ok(path)
}

fn write_bind_configs(
    work_dir: &Path,
    named_config: &Path,
    rndc_config: &Path,
    dns_port: u16,
    rndc_port: u16,
) -> io::Result<()> {
    let directory = named_conf_string(work_dir)?;
    let named_text = format!(
        r#"
key "rndc-key" {{
    algorithm hmac-sha256;
    secret "{RNDC_SECRET}";
}};
options {{
    directory "{directory}";
    allow-new-zones yes;
    recursion no;
    listen-on port {dns_port} {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    pid-file "{directory}/named.pid";
    session-keyfile "{directory}/session.key";
    managed-keys-directory "{directory}";
}};
controls {{
    inet 127.0.0.1 port {rndc_port} allow {{ 127.0.0.1; }} keys {{ "rndc-key"; }};
}};
"#
    );
    let rndc_text = format!(
        r#"
key "rndc-key" {{
    algorithm hmac-sha256;
    secret "{RNDC_SECRET}";
}};
options {{
    default-server 127.0.0.1;
    default-port {rndc_port};
    default-key "rndc-key";
}};
"#
    );
    fs::write(named_config, named_text)?;
    fs::write(rndc_config, rndc_text)?;
    Ok(())
}

fn named_conf_string(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 test path"))?;
    if value.chars().any(char::is_control) || value.contains('"') || value.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test path cannot be represented safely in named.conf",
        ));
    }
    Ok(value.to_string())
}

fn free_tcp_port() -> io::Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn free_udp_port() -> io::Result<u16> {
    Ok(UdpSocket::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn start_named(binary: &Path, config: &Path, dns_port: u16, work_dir: &Path) -> io::Result<Child> {
    Command::new(binary)
        .arg("-g")
        .arg("-c")
        .arg(config)
        .arg("-p")
        .arg(dns_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(work_dir.join("named.log"))?))
        .spawn()
}

fn start_api(
    binary: &str,
    api_port: u16,
    zones_dir: &Path,
    rndc_bin: &Path,
    rndc_config: &Path,
    work_dir: &Path,
) -> io::Result<Child> {
    Command::new(binary)
        .env("API_ADDR", format!("127.0.0.1:{}", api_port))
        .env("API_TOKEN", "bind-e2e-test-token")
        .env("API_TOKEN_PATH", work_dir.join("tokens"))
        .env("ZONES_DIR", zones_dir)
        .env("RNDC_BIN", rndc_bin)
        .env("RNDC_CONF", rndc_config)
        .env("RNDC_TIMEOUT_SECS", "5")
        .env("CHECKZONE_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(work_dir.join("api.log"))?))
        .spawn()
}

struct ChildGuard(Child);

impl ChildGuard {
    fn stop(&mut self) -> io::Result<()> {
        stop_child(&mut self.0)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = stop_child(&mut self.0);
    }
}

struct TempDirectory(PathBuf);

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stop_child(child: &mut Child) -> io::Result<()> {
    match child.try_wait()? {
        Some(_) => Ok(()),
        None => {
            child.kill()?;
            child.wait()?;
            Ok(())
        }
    }
}

async fn wait_for_named(child: &mut Child, dns_port: u16) -> io::Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], dns_port));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "named exited before opening its DNS listener",
            ));
        }
        if query_a(address, TEST_OWNER).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for named DNS listener",
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_api(
    client: &Client,
    base_url: &str,
    child: &mut Child,
) -> Result<(), Box<dyn std::error::Error>> {
    let health_url = format!("{}/health", base_url);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "SquillaDNS exited before becoming ready",
            )
            .into());
        }
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for SquillaDNS health endpoint",
            )
            .into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_a_record(
    dns_port: u16,
    expected: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = expected.map(str::parse::<Ipv4Addr>).transpose()?;
    let address = SocketAddr::from(([127, 0, 0, 1], dns_port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(actual) = query_a(address, TEST_OWNER) {
            if actual == expected {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "DNS answer for {} did not become {:?}",
                    TEST_OWNER, expected
                ),
            )
            .into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut packet = vec![0x42, 0x17, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    packet
}

fn query_a(address: SocketAddr, name: &str) -> io::Result<Option<Ipv4Addr>> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(700)))?;
    socket.send_to(&dns_query(name), address)?;
    let mut response = [0u8; 4096];
    let (size, _) = socket.recv_from(&mut response)?;
    let response = &response[..size];
    if response.len() < 12 || response[0..2] != [0x42, 0x17] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS response",
        ));
    }
    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut cursor = 12;
    for _ in 0..question_count {
        skip_dns_name(response, &mut cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|cursor| *cursor <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS question"))?;
    }
    for _ in 0..answer_count {
        skip_dns_name(response, &mut cursor)?;
        let header_end = cursor
            .checked_add(10)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS answer"))?;
        let record_type = u16::from_be_bytes([response[cursor], response[cursor + 1]]);
        let class = u16::from_be_bytes([response[cursor + 2], response[cursor + 3]]);
        let data_len = u16::from_be_bytes([response[cursor + 8], response[cursor + 9]]) as usize;
        cursor = header_end;
        let data_end = cursor
            .checked_add(data_len)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS RDATA"))?;
        if record_type == 1 && class == 1 && data_len == 4 {
            return Ok(Some(Ipv4Addr::new(
                response[cursor],
                response[cursor + 1],
                response[cursor + 2],
                response[cursor + 3],
            )));
        }
        cursor = data_end;
    }
    Ok(None)
}

fn skip_dns_name(packet: &[u8], cursor: &mut usize) -> io::Result<()> {
    loop {
        let length = *packet
            .get(*cursor)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS name"))?;
        if length & 0xc0 == 0xc0 {
            if *cursor + 1 >= packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated DNS pointer",
                ));
            }
            *cursor += 2;
            return Ok(());
        }
        *cursor += 1;
        if length == 0 {
            return Ok(());
        }
        *cursor = cursor
            .checked_add(length as usize)
            .filter(|cursor| *cursor <= packet.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS label"))?;
    }
}
