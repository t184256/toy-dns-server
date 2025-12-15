use regex::Regex;
use std::io::{BufRead, BufReader};
use std::sync::{Mutex, OnceLock};
use tokio::process::Command;

const TEST_ADDR: &str = "127.0.0.1";

static UDP_PORT: OnceLock<u16> = OnceLock::new();
static TCP_PORT: OnceLock<u16> = OnceLock::new();
static SERVER_CHILD: OnceLock<Mutex<std::process::Child>> = OnceLock::new();

async fn ensure_server_started() {
    use std::sync::Once;

    static INIT: Once = Once::new();

    // Use Once to ensure only one thread starts the server
    INIT.call_once(|| {
        let mut child =
            std::process::Command::new(env!("CARGO_BIN_EXE_toy-dns-server"))
                .arg("--listen")
                .arg("127.0.0.1:0")
                .arg("--config")
                .arg("tests/example_zone.yaml")
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("Failed to start DNS server");

        let stderr = child.stderr.take().expect("Failed to capture stderr");

        // Store the child process immediately
        SERVER_CHILD.set(Mutex::new(child)).ok();

        // Spawn a thread to read stderr and extract ports
        // This thread keeps stderr open to prevent server from getting SIGPIPE
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            let re_udp = Regex::new(r"127\.0\.0\.1:(\d+) \(UDP\)").unwrap();
            let re_tcp = Regex::new(r"127\.0\.0\.1:(\d+) \(TCP\)").unwrap();

            for line in reader.lines().map_while(Result::ok) {
                eprintln!("server> {}", line);

                if UDP_PORT.get().is_none()
                    && let Some(port_str) = re_udp.captures(&line)
                    && let Ok(port) = port_str[1].parse::<u16>()
                {
                    UDP_PORT.set(port).ok();
                }

                if TCP_PORT.get().is_none()
                    && let Some(port_str) = re_tcp.captures(&line)
                    && let Ok(port) = port_str[1].parse::<u16>()
                {
                    TCP_PORT.set(port).ok();
                }
            }
        });

        // Register cleanup handler to kill server when tests exit
        extern "C" fn cleanup() {
            stop_server();
        }
        unsafe {
            libc::atexit(cleanup);
        }
    });

    // Wait for ports to be available
    while UDP_PORT.get().is_none() || TCP_PORT.get().is_none() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn stop_server() {
    if let Some(child_mutex) = SERVER_CHILD.get()
        && let Ok(mut child) = child_mutex.lock()
    {
        eprintln!("Stopping DNS server...");
        let _ = child.kill();
        let _ = child.wait();
    }
}

async fn dig(
    server: &str,
    port: u16,
    domain: &str,
    record_type: &str,
    use_tcp: bool,
) -> String {
    let mut cmd = Command::new("dig");
    cmd.arg(format!("@{server}"))
        .arg("-p")
        .arg(port.to_string())
        .arg(domain)
        .arg(record_type);

    if use_tcp {
        cmd.arg("+tcp");
    }

    let output = cmd.output().await.expect("Failed to run dig");
    String::from_utf8(output.stdout).expect("Invalid UTF-8 from dig")
}

#[tokio::test]
async fn test_udp_a_query() {
    ensure_server_started().await;

    let output =
        dig(TEST_ADDR, *UDP_PORT.get().unwrap(), "example.com", "A", false)
            .await;

    // Check for NOERROR status
    assert!(output.contains("status: NOERROR"), "Expected NOERROR status");

    // Check that we got the expected A records
    assert!(output.contains("23.192.228.80"), "Expected IP 23.192.228.80");
    assert!(output.contains("23.192.228.84"), "Expected IP 23.192.228.84");

    // Check answer count
    assert!(output.contains("ANSWER: 2"), "Expected 2 answers");
}

#[tokio::test]
async fn test_tcp_a_query() {
    ensure_server_started().await;

    let output =
        dig(TEST_ADDR, *TCP_PORT.get().unwrap(), "example.com", "A", true)
            .await;

    // Check for NOERROR status
    assert!(output.contains("status: NOERROR"), "Expected NOERROR status");

    // Check that we got the expected A records
    assert!(output.contains("23.192.228.80"), "Expected IP 23.192.228.80");
    assert!(output.contains("23.192.228.84"), "Expected IP 23.192.228.84");

    // Check answer count
    assert!(output.contains("ANSWER: 2"), "Expected 2 answers");
}

#[tokio::test]
async fn test_udp_aaaa_query() {
    ensure_server_started().await;

    let output =
        dig(TEST_ADDR, *UDP_PORT.get().unwrap(), "example.com", "AAAA", false)
            .await;

    // Check for NOERROR status
    assert!(output.contains("status: NOERROR"), "Expected NOERROR status");

    // Check that we got AAAA records
    assert!(output.contains("2600:1406"), "Expected IPv6 address");

    // Check answer count
    assert!(output.contains("ANSWER: 2"), "Expected 2 answers");
}

#[tokio::test]
async fn test_tcp_cname_query() {
    ensure_server_started().await;

    let output = dig(
        TEST_ADDR,
        *TCP_PORT.get().unwrap(),
        "alias.example.org",
        "CNAME",
        true,
    )
    .await;

    // Check for NOERROR status
    assert!(output.contains("status: NOERROR"), "Expected NOERROR status");

    // Check that we got the expected CNAME
    assert!(
        output.contains("something-else.example.org"),
        "Expected CNAME target"
    );

    // Check answer count
    assert!(output.contains("ANSWER: 1"), "Expected 1 answer");
}

#[tokio::test]
async fn test_udp_nxdomain() {
    ensure_server_started().await;

    let output = dig(
        TEST_ADDR,
        *UDP_PORT.get().unwrap(),
        "nonexistent.example.com",
        "A",
        false,
    )
    .await;

    // Check for NXDOMAIN status
    assert!(output.contains("status: NXDOMAIN"), "Expected NXDOMAIN status");

    // Check answer count is 0
    assert!(output.contains("ANSWER: 0"), "Expected 0 answers");
}
