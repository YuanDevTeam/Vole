//! Linux local Controller listener; path ownership lives through Stop or drop.
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Listener {
    listener: tokio::net::UnixListener,
    _path: OwnedPath,
}
impl Listener {
    pub(super) fn bind(path: &str, root: &Path) -> io::Result<Self> {
        let path = root.join(path);
        // No pre-existing object is ours, including a stale socket or symlink.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Controller Unix path already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::unix(&path)?)?;
        let owned = OwnedPath::capture(path)?;
        std::fs::set_permissions(&owned.path, std::fs::Permissions::from_mode(0o600))?;
        socket.listen(128)?;
        let listener = tokio::net::UnixListener::from_std(socket.into())?;
        Ok(Self {
            listener,
            _path: owned,
        })
    }
    pub(super) async fn accept(&self) -> io::Result<tokio::net::UnixStream> {
        self.listener.accept().await.map(|(stream, _)| stream)
    }
}
struct OwnedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl OwnedPath {
    fn capture(path: PathBuf) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Controller Unix path changed during bind",
            ));
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}
impl Drop for OwnedPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
