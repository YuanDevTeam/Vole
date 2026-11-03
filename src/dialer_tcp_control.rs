//! Opt-in control of one IO-owned TCP socket. A weak capability never owns
//! the socket, and owner teardown invalidates it before closing the fd.
use crate::dispatch::BoxStream;
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, RawFd},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug)]
pub(crate) struct Control(Weak<Mutex<Option<RawFd>>>);

#[derive(Clone, Debug, Default)]
pub(crate) struct Capture(Arc<Mutex<Captured>>);
#[derive(Debug, Default)]
enum Captured {
    #[default]
    Empty,
    One(Control),
    Unavailable,
}
impl Capture {
    pub(crate) fn report(&self, control: Option<Control>) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = match (&*state, control) {
            (Captured::Empty, Some(control)) => Captured::One(control),
            _ => Captured::Unavailable,
        };
    }
    pub(crate) fn finish(&self) -> Option<Control> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::mem::replace(&mut *state, Captured::Unavailable) {
            Captured::One(control) => Some(control),
            _ => None,
        }
    }
}

struct Owner {
    io: BoxStream,
    alive: Arc<Mutex<Option<RawFd>>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        // This lock also guards every borrowed syscall. The owned IO remains
        // live until after the slot is cleared and this Drop returns.
        self.alive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}
impl AsyncRead for Owner {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Owner {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(super) fn stream(io: super::PhysicalStream) -> (BoxStream, Control) {
    let fd = io.as_raw_fd();
    owned(Box::new(io), fd)
}
pub(super) fn fast_open(
    io: crate::resources::observation::ObservedIo<super::fast_open::PendingFastOpen>,
) -> (BoxStream, Control) {
    let fd = io.as_raw_fd();
    owned(Box::new(io), fd)
}
// Only the two typed constructors above supply real production descriptors.
fn owned(io: BoxStream, fd: RawFd) -> (BoxStream, Control) {
    let alive = Arc::new(Mutex::new(Some(fd)));
    let control = Control(Arc::downgrade(&alive));
    (Box::new(Owner { io, alive }), control)
}
impl Control {
    fn borrow<T>(&self, apply: impl FnOnce(BorrowedFd<'_>) -> io::Result<T>) -> io::Result<T> {
        let state = self.0.upgrade().ok_or(io::ErrorKind::NotConnected)?;
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fd = state.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        // SAFETY: owner Drop must acquire this same lock before closing the
        // socket. The borrowed fd cannot outlive this synchronous closure.
        apply(unsafe { BorrowedFd::borrow_raw(*fd) })
    }
    pub(crate) fn apply_brutal(&self, rate: u64) -> io::Result<()> {
        // The official module accepts 500 Kbps..1 Tbps. Invalid negotiated
        // speeds must not switch CC then strand it at its 1 Mbps default.
        if !(62_500..=125_000_000_000).contains(&rate) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.borrow(|fd| {
            let old = congestion(fd)?;
            set(fd, libc::TCP_CONGESTION, b"brutal")?;
            let mut params = [0; 12];
            params[..8].copy_from_slice(&rate.to_ne_bytes());
            params[8..].copy_from_slice(&20_u32.to_ne_bytes());
            if let Err(error) = set(fd, 23301, &params) {
                if set(fd, libc::TCP_CONGESTION, &old).is_err() {
                    // SAFETY: fd remains owned and locked for this operation.
                    unsafe {
                        libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR);
                    }
                }
                return Err(error);
            }
            Ok(())
        })
    }
}

fn congestion(fd: BorrowedFd<'_>) -> io::Result<[u8; 16]> {
    let mut old = [0_u8; 16];
    let mut length = old.len() as libc::socklen_t;
    // SAFETY: output has the advertised writable size and fd is borrowed.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            old.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length == 0 || length as usize > old.len() || !old.contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(old)
}
fn set(fd: BorrowedFd<'_>, option: libc::c_int, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: bytes remains readable for its declared length; fd is borrowed.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            option,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_rejects_missing_duplicate_and_consumed_owners() {
        let capture = Capture::default();
        assert!(capture.finish().is_none());
        let (io, _) = tokio::io::duplex(1);
        let (owner, control) = owned(Box::new(io), -1);
        let capture = Capture::default();
        capture.report(Some(control.clone()));
        assert!(capture.finish().is_some());
        assert!(capture.finish().is_none());
        let capture = Capture::default();
        capture.report(Some(control.clone()));
        capture.report(Some(control.clone()));
        assert!(capture.finish().is_none());
        let capture = Capture::default();
        capture.report(None);
        capture.report(Some(control.clone()));
        assert!(capture.finish().is_none());
        drop(owner);
        // A later IO owner can be assigned the same synthetic descriptor;
        // the old weak capability must still fail before any syscall.
        let (io, _) = tokio::io::duplex(1);
        let (_replacement, _) = owned(Box::new(io), -1);
        assert_eq!(
            control
                .borrow::<()>(|_| panic!("closed owner exposed descriptor"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[test]
    fn invalid_rate_does_not_touch_an_owner_or_change_congestion() {
        let control = Control(Weak::new());
        assert_eq!(
            control.apply_brutal(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            control.apply_brutal(125_000_000_001).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
