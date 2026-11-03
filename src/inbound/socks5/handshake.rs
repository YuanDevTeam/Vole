use std::{io, net::SocketAddr, sync::Arc};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::ProxyCredentials,
    dispatch::DispatchError,
    session::Destination,
    socks5::{self, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, VERSION},
};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 handshake")
}

pub(super) struct Negotiated {
    pub command: u8,
    pub destination: Destination,
    pub user: Option<Arc<str>>,
}

/// Fixed-size, exact reads leave pipelined application bytes in the socket.
pub(super) async fn negotiate<S>(
    stream: &mut S,
    auth: Option<&ProxyCredentials>,
) -> io::Result<Negotiated>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.read_u8().await? != VERSION {
        return Err(invalid());
    }
    let count = stream.read_u8().await? as usize;
    let mut methods = [0_u8; 255];
    stream.read_exact(&mut methods[..count]).await?;
    let method = if auth.is_some() { 2 } else { 0 };
    if !methods[..count].contains(&method) {
        stream.write_all(&[VERSION, 0xff]).await?;
        return Err(invalid());
    }
    stream.write_all(&[VERSION, method]).await?;
    let mut authenticated_user = None;
    if let Some(auth) = auth {
        let version = stream.read_u8().await?;
        let user_length = stream.read_u8().await? as usize;
        let mut user = [0_u8; 255];
        stream.read_exact(&mut user[..user_length]).await?;
        let password_length = stream.read_u8().await? as usize;
        let mut password = [0_u8; 255];
        stream.read_exact(&mut password[..password_length]).await?;
        authenticated_user = (version == 1)
            .then(|| auth.authenticate(&user[..user_length], &password[..password_length]))
            .flatten();
        let valid = authenticated_user.is_some();
        stream.write_all(&[1, u8::from(!valid)]).await?;
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ));
        }
    }
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        reply(stream, 1, None).await?;
        return Err(invalid());
    }
    if !matches!(header[1], COMMAND_CONNECT | COMMAND_UDP_ASSOCIATE) {
        reply(stream, 7, None).await?;
        return Err(invalid());
    }
    match socks5::read_destination(stream, header[1] == COMMAND_UDP_ASSOCIATE).await {
        Ok(destination) => Ok(Negotiated {
            command: header[1],
            destination,
            user: authenticated_user,
        }),
        Err(error) => {
            reply(stream, 8, None).await?;
            Err(error)
        }
    }
}

pub(super) async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u8,
    bound: Option<SocketAddr>,
) -> io::Result<()> {
    let mut response = vec![VERSION, status, 0];
    socks5::encode_address(
        &Destination::Ip(bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))),
        &mut response,
    )?;
    stream.write_all(&response).await
}

pub(super) fn status(error: &DispatchError) -> u8 {
    match error {
        DispatchError::NotAllowed => 2,
        DispatchError::NetworkUnreachable => 3,
        DispatchError::HostUnreachable => 4,
        DispatchError::ConnectionRefused => 5,
        DispatchError::TimedOut => 6,
        DispatchError::Other(_) | DispatchError::RuleEvaluation(_) => 1,
    }
}
