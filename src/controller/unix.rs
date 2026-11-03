//! Linux local Controller listener; path ownership lives through Stop or drop.
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
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
        let socket = new_socket()?;
        socket.bind(&SockAddr::unix(&path)?)?;
        let owned = OwnedPath::capture(path)?;
        owned.prepare_for_listen()?;
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
fn new_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    // Linux bind inherits this inode mode, even if the new path is then moved.
    if unsafe { libc::fchmod(socket.as_raw_fd(), 0o600) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}
struct OwnedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl OwnedPath {
    fn prepare_for_listen(&self) -> io::Result<()> {
        self.require_current()?;
        // Restore owner bits that a restrictive process umask may have removed.
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        self.require_current()
    }

    fn require_current(&self) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_socket()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Controller Unix path changed before listen",
            ));
        }
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    struct Umask(libc::mode_t);
    impl Umask {
        fn set(mask: libc::mode_t) -> Self {
            Self(unsafe { libc::umask(mask) })
        }
    }
    impl Drop for Umask {
        fn drop(&mut self) {
            unsafe { libc::umask(self.0) };
        }
    }

    #[test]
    #[ignore = "requires isolated Linux container; run this module with --test-threads=1"]
    fn socket_is_owner_only_before_path_permissions_are_applied() {
        let root = tempfile::tempdir().unwrap();
        let _umask = Umask::set(0);
        let path = root.path().join("controller.sock");
        let socket = new_socket().unwrap();
        socket.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        let owned = OwnedPath::capture(path.clone()).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().mode() & 0o777,
            0o600
        );
        owned.prepare_for_listen().unwrap();
        drop(owned);
        assert!(!path.exists());
    }

    #[test]
    #[ignore = "requires isolated Linux container; run this module with --test-threads=1"]
    fn moved_socket_stays_private_and_replacement_is_not_prepared_or_removed() {
        let root = tempfile::tempdir().unwrap();
        let _umask = Umask::set(0);
        let path = root.path().join("controller.sock");
        let moved = root.path().join("moved.sock");
        let socket = new_socket().unwrap();
        socket.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        let owned = OwnedPath::capture(path.clone()).unwrap();
        std::fs::rename(&path, &moved).unwrap();
        let _replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let replacement_inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let error = owned.prepare_for_listen().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(
            std::fs::symlink_metadata(&moved).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().mode() & 0o777,
            0o777
        );
        drop(owned);
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().ino(),
            replacement_inode
        );
    }

    #[tokio::test]
    #[ignore = "requires isolated Linux container; run this module with --test-threads=1"]
    async fn restrictive_umask_preserves_exact_permissions_accept_and_drop_cleanup() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = tempfile::tempdir().unwrap();
        let _umask = Umask::set(0o777);
        let path = root.path().join("controller.sock");
        let listener = Listener::bind("controller.sock", root.path()).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().mode() & 0o777,
            0o600
        );
        let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut accepted = listener.accept().await.unwrap();
        client.write_all(b"control").await.unwrap();
        let mut bytes = [0; 7];
        accepted.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"control");
        drop(listener);
        assert!(!path.exists());
    }
}
