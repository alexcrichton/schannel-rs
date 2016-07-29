extern crate env_logger;

use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpStream, TcpListener};
use std::thread;
use winapi;

use cert_context::CertContext;
use cert_store::CertStore;
use schannel_cred::{Direction, Protocol, Algorithm, SchannelCred};
use tls_stream::{self, HandshakeError};

#[test]
fn basic() {
    let creds = SchannelCred::builder().acquire(Direction::Outbound).unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

#[test]
fn invalid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Rc2, Algorithm::Ecdsa])
        .acquire(Direction::Outbound);
    assert_eq!(creds.err().unwrap().raw_os_error().unwrap(),
               winapi::SEC_E_ALGORITHM_MISMATCH as i32);
}

#[test]
fn valid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Aes128, Algorithm::Ecdsa])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

fn unwrap_handshake<S>(e: HandshakeError<S>) -> io::Error {
    match e {
        HandshakeError::Failure(e) => e,
        HandshakeError::Interrupted(_) => panic!("not an I/O error"),
    }
}

#[test]
#[ignore] // google's inconsistent about disallowing sslv3
fn invalid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Ssl3])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(err.raw_os_error().unwrap(),
               winapi::SEC_E_UNSUPPORTED_FUNCTION as i32);
}

#[test]
fn valid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

#[test]
fn expired_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("expired.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("expired.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(err.raw_os_error().unwrap(), winapi::CERT_E_EXPIRED as i32);
}

#[test]
fn self_signed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(err.raw_os_error().unwrap(),
               winapi::CERT_E_UNTRUSTEDROOT as i32);
}

#[test]
fn wrong_host_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("wrong.host.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(err.raw_os_error().unwrap(),
               winapi::CERT_E_CN_NO_MATCH as i32);
}

#[test]
fn shutdown() {
    let creds = SchannelCred::builder().acquire(Direction::Outbound).unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.shutdown().unwrap();
}

#[test]
fn validation_failure_is_permanent() {
    let creds = SchannelCred::builder().acquire(Direction::Outbound).unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    // temporarily switch to nonblocking to allow us to construct the stream
    // without validating
    stream.set_nonblocking(true).unwrap();
    let stream = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .initialize(creds, stream);
    let stream = match stream {
        Err(HandshakeError::Interrupted(s)) => s,
        _ => panic!(),
    };
    stream.get_ref().set_nonblocking(false).unwrap();
    let err = unwrap_handshake(stream.handshake().err().unwrap());
    assert_eq!(err.raw_os_error().unwrap(),
               winapi::CERT_E_UNTRUSTEDROOT as i32);
}

fn can_trust_localhost_der() -> bool {
    if env::var("SCHANNEL_RS_SKIP_SERVER_TESTS").is_ok() {
        return false
    }
    let cert = include_bytes!("../test/schannel-ca.der");
    let cert = CertContext::new(cert).unwrap();
    let hash_to_find = cert.signature_hash().unwrap();
    let mut root = CertStore::system("Root").unwrap();
    let mut my = CertStore::system("My").unwrap();
    for cert in root.iter().chain(my.iter()) {
        let hash = cert.signature_hash().unwrap();
        if hash == hash_to_find {
            return true
        }
    }

    panic!("\n\n\
To run all schannel-rs tests successfully a custom root certificate needs to be
added to the system store of trusted certificates. Our certificate was not found
in either the root or local users's set of trusted root certificates, so these
tests will fail unless this is done.

Please follow the instructions in the README.md about adding this library's
certificate to the system trust store. In short, though, simply:

    start test/schannel-ca.crt

Then follow the dialogs to install the certificate into your local set of
trusted root certificates.

To ignore these tests, simply:

    export SCHANNEL_RS_SKIP_SERVER_TESTS=1
\n\n\
");
}

#[test]
fn accept_a_socket() {
    if !can_trust_localhost_der() {
        return
    }

    drop(env_logger::init());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
                                 .acquire(Direction::Outbound).unwrap();
        let mut store = CertStore::memory().unwrap();
        let cert = include_bytes!("../test/localhost.der");
        store.add_encoded_certificate(cert).unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .cert_store(store.into_store())
            .initialize(creds, stream)
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    });

    let stream = listener.accept().unwrap().0;
    let pkcs12 = include_bytes!("../test/localhost.p12");
    let mut store = CertStore::import_pkcs12(pkcs12, "foobar").unwrap();
    let cert = store.iter().next().unwrap();
    let creds = SchannelCred::builder()
                        .cert(cert)
                        .acquire(Direction::Inbound)
                        .unwrap();
    let mut stream = tls_stream::Builder::new()
        .accept(true)
        .initialize(creds, stream)
        .unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    t.join().unwrap();
}
