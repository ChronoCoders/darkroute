//! Minimal SOCKS5 CONNECT-only server (RFC 1928). No auth, no BIND, no UDP.

use std::sync::Arc;

use darkroute_client::DarkrouteClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("client SDK: {0}")]
    Client(#[from] darkroute_client::ClientError),
    #[error("unsupported SOCKS version 0x{0:02x}")]
    UnsupportedVersion(u8),
    #[error("unsupported SOCKS command 0x{0:02x}")]
    UnsupportedCommand(u8),
    #[error("unsupported address type 0x{0:02x}")]
    UnsupportedAtyp(u8),
    #[error("client did not offer NO_AUTH")]
    NoAcceptableAuth,
}

pub async fn serve(
    mut sock: TcpStream,
    client: Arc<Mutex<DarkrouteClient>>,
) -> Result<(), SocksError> {
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet[0] != VER {
        return Err(SocksError::UnsupportedVersion(greet[0]));
    }
    let nmethods = greet[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = sock.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await;
        return Err(SocksError::NoAcceptableAuth);
    }
    sock.write_all(&[VER, METHOD_NO_AUTH]).await?;

    let mut req_head = [0u8; 4];
    sock.read_exact(&mut req_head).await?;
    if req_head[0] != VER {
        return Err(SocksError::UnsupportedVersion(req_head[0]));
    }
    let cmd = req_head[1];
    if cmd != CMD_CONNECT {
        write_reply(&mut sock, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(SocksError::UnsupportedCommand(cmd));
    }
    let atyp = req_head[3];
    let dest_host = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            let v6 = std::net::Ipv6Addr::from(a);
            v6.to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(s) => s,
                Err(_) => {
                    write_reply(&mut sock, REP_ADDRESS_NOT_SUPPORTED).await?;
                    return Err(SocksError::UnsupportedAtyp(atyp));
                }
            }
        }
        other => {
            write_reply(&mut sock, REP_ADDRESS_NOT_SUPPORTED).await?;
            return Err(SocksError::UnsupportedAtyp(other));
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);

    let circuit_result = async {
        let mut c = client.lock().await;
        let (m_raw, token) = c.issue_token().await?;
        let route = c.get_circuit().await?;
        c.dial(&dest_host, dest_port, &m_raw, &token, &route).await
    }
    .await;
    let circuit = match circuit_result {
        Ok(c) => c,
        Err(e) => {
            let _ = write_reply(&mut sock, REP_GENERAL_FAILURE).await;
            return Err(SocksError::Client(e));
        }
    };

    write_reply(&mut sock, REP_SUCCESS).await?;

    let (mut s_read, mut s_write) = tokio::io::split(sock);
    let (mut c_read, mut c_write) = tokio::io::split(circuit);
    let fwd = async { tokio::io::copy(&mut s_read, &mut c_write).await };
    let bck = async { tokio::io::copy(&mut c_read, &mut s_write).await };
    let _ = tokio::join!(fwd, bck);
    Ok(())
}

async fn write_reply(sock: &mut TcpStream, rep: u8) -> Result<(), std::io::Error> {
    sock.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
