//! Startups that ask the proxy for a newer protocol minor version or for protocol options.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::Stdio;
use std::time::Duration;

use bytes::BytesMut;
use postgres_protocol::message::frontend;

use crate::support::{printed, project_with_reader, run_command, run_in, sweeping, text};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// One backend message: its tag and its body.
fn read_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    stream.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut body = vec![0; len - 4];
    stream.read_exact(&mut body).unwrap();
    (header[0], body)
}

/// Every backend message up to and including `ReadyForQuery`.
fn frames_until_ready(stream: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut frames = vec![read_frame(stream)];
    while frames.last().unwrap().0 != b'Z' {
        frames.push(read_frame(stream));
    }
    frames
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn psql_asking_for_protocol_3_2_reads_through_the_proxy() {
    let dir = project_with_reader("e2e-protocol-psql");

    // libpq 18 and later negotiate down from 3.2. Older libpq ignores the variable, so for
    // those clients the raw startup test below is what proves the 3.2 path.
    let output = run_in(
        &dir,
        &["sh", "-c", "PGMAXPROTOCOLVERSION=3.2 psql -Atc 'SELECT 42'"],
    );

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert!(!text(&output.stderr).contains("dbvalet:"));
    assert_eq!(text(&output.stdout), "42\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_protocol_3_2_startup_with_a_protocol_option_logs_in_and_runs_a_query() {
    let dir = project_with_reader("e2e-protocol-raw");
    let _sweeping = sweeping();
    let mut run = run_command(
        &dir,
        &[
            "sh",
            "-c",
            "echo \"port=$PGPORT\"; echo \"token=$PGPASSWORD\"; echo READY; read line",
        ],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut seen = String::new();
    while !seen.ends_with("READY\n") {
        assert_ne!(
            stdout.read_line(&mut seen).unwrap(),
            0,
            "the child exited early"
        );
    }
    let mut proxy =
        TcpStream::connect(("127.0.0.1", printed(&seen, "port").parse().unwrap())).unwrap();
    proxy.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

    proxy
        .write_all(b"\0\0\0\x21\0\x03\0\x02user\0agent\0_pq_.foo\0bar\0\0")
        .unwrap();
    assert_eq!(
        read_frame(&mut proxy),
        (b'v', b"\0\x03\0\0\0\0\0\x01_pq_.foo\0".to_vec())
    );
    assert_eq!(read_frame(&mut proxy), (b'R', b"\0\0\0\x03".to_vec()));
    let mut password = BytesMut::new();
    frontend::password_message(printed(&seen, "token").as_bytes(), &mut password).unwrap();
    proxy.write_all(&password).unwrap();
    assert_eq!(read_frame(&mut proxy), (b'R', b"\0\0\0\0".to_vec()));
    frames_until_ready(&mut proxy);
    let mut query = BytesMut::new();
    frontend::query("SELECT 42", &mut query).unwrap();
    proxy.write_all(&query).unwrap();
    let answer = frames_until_ready(&mut proxy);
    drop(proxy);
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();

    assert!(
        answer.contains(&(b'D', b"\0\x01\0\0\0\x0242".to_vec())),
        "{answer:?}"
    );
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert!(!text(&output.stderr).contains("dbvalet:"));
}
