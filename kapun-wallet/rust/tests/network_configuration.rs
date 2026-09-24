/* Copyright 2026 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use std::{io::BufReader, sync::Arc, time::Duration};

use rustls::{Certificate, PrivateKey, ServerConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

const TEST_USER_AGENT: &str = "kapun-sdk-network-test/1.0";
const TEST_FEDERATION_JWT: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.";

struct NetworkConfigurationReset;

impl Drop for NetworkConfigurationReset {
    fn drop(&mut self) {
        kapun_wallet_rust::uniffi_reqwest::set_untrusted_tls(false);
        kapun_wallet_rust::set_user_agent(None);
    }
}

async fn spawn_self_signed_https_server(
    response_body: &'static str,
) -> (String, oneshot::Receiver<String>) {
    let mut certificate_reader =
        BufReader::new(include_bytes!("fixtures/localhost-cert.pem").as_slice());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .expect("test certificate should be valid PEM")
        .into_iter()
        .map(Certificate)
        .collect();
    let mut key_reader = BufReader::new(include_bytes!("fixtures/localhost-key.pem").as_slice());
    let private_key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .expect("test private key should be valid PEM")
        .into_iter()
        .next()
        .map(PrivateKey)
        .expect("test private key should be present");
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .expect("test certificate and key should match");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    let (request_sender, request_receiver) = oneshot::channel();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test connection should arrive");
            let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                // The verified client rejects this self-signed certificate during the first
                // connection. Keep serving so the explicitly untrusted client can reconnect.
                continue;
            };

            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = tls_stream
                    .read(&mut buffer)
                    .await
                    .expect("test request should be readable");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            tls_stream
                .write_all(response.as_bytes())
                .await
                .expect("test response should be writable");
            let _ = request_sender.send(String::from_utf8_lossy(&request).into_owned());
            break;
        }
    });

    (
        format!("https://localhost:{}/", address.port()),
        request_receiver,
    )
}

#[tokio::test]
async fn sdk_reqwest_client_applies_tls_policy_and_user_agent() {
    let _reset = NetworkConfigurationReset;
    let (url, request_receiver) = spawn_self_signed_https_server("ok").await;

    kapun_wallet_rust::uniffi_reqwest::set_untrusted_tls(false);
    let verified_result = kapun_wallet_rust::get_reqwest_client()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("verified client should build")
        .get(&url)
        .send()
        .await;
    assert!(
        verified_result.is_err(),
        "a self-signed certificate must be rejected when untrusted TLS is disabled"
    );

    kapun_wallet_rust::set_user_agent(Some(TEST_USER_AGENT.to_owned()));
    kapun_wallet_rust::uniffi_reqwest::set_untrusted_tls(true);
    let response = kapun_wallet_rust::get_reqwest_client()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("untrusted client should build")
        .get(&url)
        .send()
        .await
        .expect("self-signed certificate should be accepted when untrusted TLS is enabled");
    assert!(response.status().is_success());

    let request = request_receiver
        .await
        .expect("server should capture a request");
    assert!(
        request
            .lines()
            .any(|line| { line.eq_ignore_ascii_case(&format!("user-agent: {TEST_USER_AGENT}")) }),
        "configured user-agent was not sent; request was:\n{request}"
    );
}

#[tokio::test]
async fn federation_fetch_applies_tls_policy_and_user_agent() {
    let _reset = NetworkConfigurationReset;
    let (url, request_receiver) = spawn_self_signed_https_server(TEST_FEDERATION_JWT).await;

    kapun_wallet_rust::set_user_agent(Some(TEST_USER_AGENT.to_owned()));
    kapun_wallet_rust::uniffi_reqwest::set_untrusted_tls(false);
    let verified_result = openid_federation::fetch_jwt_async::<
        serde_json::Value,
        kapun_util_rust::network::SdkDefaultConfig,
    >(&url)
    .await;
    assert!(
        verified_result.is_err(),
        "federation must reject a self-signed certificate when untrusted TLS is disabled"
    );

    kapun_wallet_rust::uniffi_reqwest::set_untrusted_tls(true);
    let jwt = openid_federation::fetch_jwt_async::<
        serde_json::Value,
        kapun_util_rust::network::SdkNoVerifyConfig,
    >(&url)
    .await
    .expect("federation should accept a self-signed certificate when enabled");
    assert_eq!(
        jwt.payload_unverified()
            .expect("test JWT should contain a payload")
            .insecure()
            .get("sub")
            .and_then(serde_json::Value::as_str),
        Some("test")
    );

    let request = request_receiver
        .await
        .expect("server should capture a federation request");
    assert!(request.lines().any(|line| {
        line.eq_ignore_ascii_case(&format!("user-agent: {TEST_USER_AGENT}"))
    }));
}
