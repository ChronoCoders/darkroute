use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::ClientError;

pub fn outbound_connector() -> Result<TlsConnector, ClientError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        let combined = native
            .errors
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ClientError::NativeRoots(std::io::Error::other(combined)));
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

pub async fn dial(
    connector: &TlsConnector,
    addr: std::net::SocketAddr,
    sni: &str,
) -> Result<TlsStream<TcpStream>, ClientError> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|_| ClientError::InvalidServerName(sni.to_string()))?;
    let tls = connector.connect(name, tcp).await?;
    Ok(tls)
}
