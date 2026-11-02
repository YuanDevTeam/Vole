use std::{fmt, io, os::fd::IntoRawFd};

use tokio::io::unix::AsyncFd;

use crate::{IpVersion, Result, TunFraming, VoleError};

use super::{TUN_PACKET_BATCH_SIZE, TunFd};

#[cfg(all(test, target_os = "linux"))]
use tests::Device;
#[cfg(not(all(test, target_os = "linux")))]
use tun_rs::SyncDevice as Device;

#[cfg(test)]
const TUN_MTU: usize = 1_500;

/// Non-blocking raw-IP packet I/O backed by tun-rs.
///
/// Vole validates and duplicates the borrowed host descriptor before this
/// type is constructed. The duplicate is then owned and closed by tun-rs.
/// We deliberately wrap tun-rs's `SyncDevice` in Tokio's `AsyncFd` instead
/// of using its async constructor: a duplicated descriptor shares file-status
/// flags with the host descriptor, and Vole must never change those flags.
pub struct TunRsIo {
    device: AsyncFd<Device>,
    framing: TunFraming,
    mtu: usize,
}

fn register_device(device: tun_rs::SyncDevice) -> io::Result<AsyncFd<Device>> {
    #[cfg(all(test, target_os = "linux"))]
    let device = Device::Native(device);
    // SAFETY: SyncDevice owns the open descriptor, and registration preserves
    // its file-status flags. The device remains owned until AsyncFd drops it.
    unsafe { AsyncFd::register(device) }.map_err(io::Error::from)
}

impl fmt::Debug for TunRsIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunRsIo")
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl TunRsIo {
    pub fn new(fd: TunFd, framing: TunFraming) -> Result<Self> {
        Self::new_with_mtu(fd, framing, 1500)
    }

    pub fn new_with_mtu(fd: TunFd, framing: TunFraming, mtu: u16) -> Result<Self> {
        validate_mtu(mtu)?;
        #[cfg(target_os = "linux")]
        if framing != TunFraming::RawIp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux TUN requires rawIp framing",
            )
            .into());
        }
        // SAFETY: TunFd owns a validated, open duplicate. Ownership moves to
        // SyncDevice, which closes only this duplicate and does not change
        // file-status flags or configure the host-owned interface.
        let device = unsafe { tun_rs::SyncDevice::from_fd(fd.into_raw_fd()) }?;
        configure_platform_framing(&device, framing);
        Ok(Self {
            device: register_device(device)?,
            framing,
            mtu: usize::from(mtu),
        })
    }

    // Socketpair fixtures share the production packet algorithms without
    // presenting an ordinary socket as a Linux TUN. This entry does not exist
    // in production; Apple still uses SyncDevice for actual PI handling.
    #[cfg(test)]
    pub(crate) fn new_mock(fd: TunFd, framing: TunFraming) -> Result<Self> {
        Self::new_mock_with_mtu(fd, framing, 1500)
    }

    #[cfg(test)]
    pub(crate) fn new_mock_with_mtu(fd: TunFd, framing: TunFraming, mtu: u16) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            validate_mtu(mtu)?;
            assert_eq!(framing, TunFraming::RawIp);
            Ok(Self {
                // SAFETY: the fixture owns the duplicate without changing its
                // shared nonblocking status; AsyncFd owns it until drop.
                device: unsafe { AsyncFd::register(Device::SocketPair(fd)) }
                    .map_err(io::Error::from)?,
                framing,
                mtu: usize::from(mtu),
            })
        }
        #[cfg(not(target_os = "linux"))]
        Self::new_with_mtu(fd, framing, mtu)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn interface_name(&self) -> io::Result<String> {
        self.device.get_ref().name()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn echo_prefixes(&self) -> io::Result<Vec<crate::config::IpCidr>> {
        use std::os::fd::AsFd;
        super::linux_tun::interface_prefixes(self.device.get_ref().as_fd())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_device(&self) -> &tun_rs::SyncDevice {
        #[cfg(test)]
        {
            self.device.get_ref().native()
        }
        #[cfg(not(test))]
        {
            self.device.get_ref()
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn open_exclusive(name: &str, mtu: u16) -> Result<Self> {
        use std::{ffi::CString, os::fd::AsRawFd};
        let name = CString::new(if name.is_empty() { "Vole" } else { name })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN name"))?;
        if name.as_bytes().len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN name is too long").into());
        }
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        // SAFETY: ifreq starts zeroed; copied name includes its terminator.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (slot, byte) in request.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
            *slot = *byte as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI | 0x8000) as libc::c_short; // IFF_TUN_EXCL
        // SAFETY: fd points to /dev/net/tun and request is a complete initialized ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &request) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: ownership moves to SyncDevice only after the exclusive ioctl succeeded.
        let device = unsafe { tun_rs::SyncDevice::from_fd(fd.into_raw_fd()) }?;
        device.set_mtu(mtu)?;
        device.set_nonblocking(true)?;
        Ok(Self {
            device: register_device(device)?,
            framing: TunFraming::RawIp,
            mtu: usize::from(mtu),
        })
    }

    /// Open a core-owned local TUN without configuring addresses or routes.
    /// Owned descriptors may be made nonblocking; borrowed ones are never changed.
    pub fn open(name: &str, mtu: u16) -> Result<Self> {
        validate_mtu(mtu)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mut builder = tun_rs::DeviceBuilder::new().mtu(mtu);
            #[cfg(target_os = "linux")]
            {
                builder = builder.name(if name.is_empty() { "Vole" } else { name });
            }
            #[cfg(target_os = "macos")]
            {
                if !name.is_empty() {
                    builder = builder.name(name);
                }
                builder = builder.associate_route(false).packet_information(true);
            }
            let device = builder.build_sync()?;
            device.set_nonblocking(true)?;
            #[cfg(target_os = "macos")]
            let framing = TunFraming::Utun;
            #[cfg(target_os = "linux")]
            let framing = TunFraming::RawIp;
            configure_platform_framing(&device, framing);
            Ok(Self {
                device: register_device(device)?,
                framing,
                mtu: usize::from(mtu),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = name;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform requires a host TUN file descriptor",
            )
            .into())
        }
    }

    #[must_use]
    pub const fn framing(&self) -> TunFraming {
        self.framing
    }

    /// Reads exactly one packet. tun-rs removes the Apple PI header and
    /// exposes raw IP on every supported fd platform.
    pub async fn read_packet(&self, packet: &mut Vec<u8>) -> Result<IpVersion> {
        packet.clear();
        packet.resize(self.mtu, 0);
        let size = loop {
            let mut ready = self.device.readable().await?;
            match ready.try_io(|inner| inner.get_ref().recv(packet)) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if size == 0 {
            return Err(VoleError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN closed",
            )));
        }
        packet.truncate(size);
        let (version, _) = TunFraming::RawIp.decode(packet)?;
        Ok(version)
    }

    /// Waits for the first packet, then drains only immediately ready packets.
    /// Each consumed packet has its own outcome, so an invalid packet cannot
    /// discard valid neighbours. A fatal error preserves the consumed prefix.
    pub(crate) async fn read_packets(
        &self,
        packets: &mut [Vec<u8>],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        debug_assert!(!packets.is_empty() && packets.len() <= TUN_PACKET_BATCH_SIZE);
        outcomes.clear();
        while outcomes.len() < packets.len() {
            let mut ready = self.device.readable().await?;
            loop {
                let packet = &mut packets[outcomes.len()];
                packet.clear();
                packet.resize(self.mtu, 0);
                match ready.try_io(|inner| inner.get_ref().recv(packet)) {
                    Ok(Ok(0)) => {
                        return Err(
                            io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed").into()
                        );
                    }
                    Ok(Ok(size)) => {
                        packet.truncate(size);
                        outcomes.push(TunFraming::RawIp.decode(packet).map(|(version, _)| version));
                        if outcomes.len() == packets.len() {
                            return Ok(());
                        }
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_would_block) if !outcomes.is_empty() => return Ok(()),
                    Err(_would_block) => break,
                }
            }
        }
        Ok(())
    }

    /// Writes independent packets while sharing a readiness observation.
    /// Outcomes are recorded immediately, including local invalid-packet
    /// drops, so failure or cancellation never hides an accepted prefix.
    pub(crate) async fn write_packets(
        &self,
        packets: &[&[u8]],
        outcomes: &mut Vec<Result<IpVersion>>,
    ) -> Result<()> {
        debug_assert!(!packets.is_empty() && packets.len() <= TUN_PACKET_BATCH_SIZE);
        outcomes.clear();
        let mut readiness = None;
        for packet in packets {
            let version = match validate_write_packet(packet, self.mtu) {
                Ok(version) => version,
                Err(error) => {
                    outcomes.push(Err(error));
                    continue;
                }
            };
            let written = loop {
                let ready = match &mut readiness {
                    Some(ready) => ready,
                    None => readiness.insert(self.device.writable().await?),
                };
                match ready.try_io(|inner| inner.get_ref().send(packet)) {
                    #[cfg(target_vendor = "apple")]
                    Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        // Only this unaccepted packet is retried. Drop the
                        // guard across the same cancellable Darwin backoff
                        // used by the single-packet path.
                        readiness = None;
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    Ok(result) => break result?,
                    Err(_would_block) => readiness = None,
                }
            };
            if written != packet.len() {
                return Err(
                    io::Error::new(io::ErrorKind::WriteZero, "partial TUN packet write").into(),
                );
            }
            outcomes.push(Ok(version));
        }
        Ok(())
    }

    /// Writes one complete packet. Partial writes are rejected because retrying
    /// a suffix would create a second malformed TUN packet.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<IpVersion> {
        let version = validate_write_packet(packet, self.mtu)?;
        let written = loop {
            let mut ready = self.device.writable().await?;
            match ready.try_io(|inner| inner.get_ref().send(packet)) {
                #[cfg(target_vendor = "apple")]
                Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    // Darwin can exhaust packet/mbuf space after a cached
                    // writable event. No packet was accepted: retain this one
                    // packet, yield without spinning, and let Stop cancel the
                    // future. Do not resize the host's shared socket buffers.
                    drop(ready);
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if written != packet.len() {
            return Err(VoleError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial TUN packet write",
            )));
        }
        Ok(version)
    }
}

fn validate_mtu(mtu: u16) -> Result<()> {
    if mtu < 1280 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN MTU").into());
    }
    Ok(())
}

fn validate_write_packet(packet: &[u8], mtu: usize) -> Result<IpVersion> {
    if packet.len() > mtu {
        return Err(VoleError::InvalidPacket(
            "TUN packet exceeds configured MTU",
        ));
    }
    TunFraming::RawIp.decode(packet).map(|(version, _)| version)
}

#[cfg(target_vendor = "apple")]
fn configure_platform_framing(device: &tun_rs::SyncDevice, framing: TunFraming) {
    // "Ignore" means expose raw IP while stripping/adding the utun PI header.
    // This changes only the adapter's in-memory framing flag, not fd flags or
    // the host interface. Raw-IP memory fixtures do not carry that header.
    device.set_ignore_packet_info(framing == TunFraming::Utun);
}

#[cfg(not(target_vendor = "apple"))]
fn configure_platform_framing(_device: &tun_rs::SyncDevice, _framing: TunFraming) {}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::net::{UnixDatagram, UnixStream},
        },
    };

    use super::*;

    // Recent tun-rs versions correctly reject socketpairs when adopting a
    // Linux TUN. Keep the real constructor intact and substitute only the fd
    // operations for these local packet-I/O fixtures. Apple fixtures continue
    // through SyncDevice so its packet-information handling remains covered.
    #[cfg(target_os = "linux")]
    pub(super) enum Device {
        Native(tun_rs::SyncDevice),
        SocketPair(TunFd),
    }

    #[cfg(target_os = "linux")]
    impl std::os::fd::AsRawFd for Device {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            match self {
                Self::Native(device) => device.as_raw_fd(),
                Self::SocketPair(fd) => fd.as_raw_fd(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl std::os::fd::AsFd for Device {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            match self {
                Self::Native(device) => std::os::fd::AsFd::as_fd(device),
                Self::SocketPair(fd) => fd.as_fd(),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Device {
        pub(super) fn native(&self) -> &tun_rs::SyncDevice {
            match self {
                Self::Native(device) => device,
                Self::SocketPair(_) => panic!("packet fixture has no native TUN interface"),
            }
        }

        pub(super) fn name(&self) -> io::Result<String> {
            match self {
                Self::Native(device) => device.name(),
                Self::SocketPair(_) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "packet fixture has no native TUN interface",
                )),
            }
        }

        pub(super) fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::Native(device) => device.recv(packet),
                Self::SocketPair(fd) => {
                    // SAFETY: the fixture owns this open duplicate, and the
                    // mutable slice supplies its full writable byte range.
                    let size = unsafe {
                        libc::read(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len())
                    };
                    if size < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(size as usize)
                    }
                }
            }
        }

        pub(super) fn send(&self, packet: &[u8]) -> io::Result<usize> {
            match self {
                Self::Native(device) => device.send(packet),
                Self::SocketPair(fd) => {
                    // SAFETY: the fixture owns this open duplicate, and the
                    // immutable slice remains live for the synchronous write.
                    let size = unsafe {
                        libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len())
                    };
                    if size < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(size as usize)
                    }
                }
            }
        }
    }

    const IPV4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    const IPV6: [u8; 40] = [
        0x60, 0, 0, 0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn real_constructor_rejects_socketpair_and_closes_only_its_duplicate() {
        let (mut host, mut peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        // SAFETY: host remains open before and after the failed adoption.
        let before = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        assert_ne!(fd.as_raw_fd(), host.as_raw_fd());
        let error = TunRsIo::new(fd, TunFraming::RawIp).unwrap_err();
        assert!(matches!(
            error,
            VoleError::Io(ref error) if error.raw_os_error() == Some(libc::ENOTTY)
        ));
        // SAFETY: the original host descriptor is still owned by this test.
        let after = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(before, after);
        host.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        peer.set_nonblocking(true).unwrap();
        drop(host);
        // EOF proves that failed adoption released the duplicate, without
        // depending on a numeric fd that another parallel test could reuse.
        assert_eq!(peer.read(&mut bytes).unwrap(), 0);
    }

    #[tokio::test]
    async fn raw_ip_read_reuses_caller_buffer_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::RawIp).unwrap();

        let mut packet = Vec::with_capacity(1500);
        for (expected, version) in [(&IPV4[..], IpVersion::V4), (&IPV6[..], IpVersion::V6)] {
            peer.send(expected).unwrap();
            assert_eq!(io.read_packet(&mut packet).await.unwrap(), version);
            assert_eq!(packet, expected);
            assert_eq!(packet.capacity(), TUN_MTU);
        }
    }

    #[tokio::test]
    async fn batch_read_preserves_valid_neighbours_of_an_invalid_packet() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::RawIp,
        )
        .unwrap();
        for packet in [&IPV4[..], &[0x70][..], &IPV6[..]] {
            peer.send(packet).unwrap();
        }
        let mut packets =
            std::array::from_fn::<_, TUN_PACKET_BATCH_SIZE, _>(|_| Vec::with_capacity(TUN_MTU));
        let mut outcomes = Vec::with_capacity(TUN_PACKET_BATCH_SIZE);
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();

        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        assert!(matches!(outcomes[1], Err(VoleError::InvalidPacket(_))));
        assert_eq!(outcomes[2].as_ref().unwrap(), &IpVersion::V6);
        assert_eq!(packets[0], IPV4);
        assert_eq!(packets[1], [0x70]);
        assert_eq!(packets[2], IPV6);
        assert!(packets.iter().all(|packet| packet.capacity() == TUN_MTU));
    }

    #[tokio::test]
    async fn batch_read_is_bounded_and_does_not_wait_to_fill() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::RawIp,
        )
        .unwrap();
        for _ in 0..=TUN_PACKET_BATCH_SIZE {
            peer.send(&IPV4).unwrap();
        }
        let mut packets = std::array::from_fn::<_, TUN_PACKET_BATCH_SIZE, _>(|_| Vec::new());
        let mut outcomes = Vec::new();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), TUN_PACKET_BATCH_SIZE);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            io.read_packets(&mut packets, &mut outcomes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(packets[0], IPV4);
    }

    #[tokio::test]
    async fn batch_read_waits_for_first_packet_and_can_be_cancelled() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::RawIp,
        )
        .unwrap();
        let mut packets = [Vec::new()];
        let mut outcomes = vec![Ok(IpVersion::V6)];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(5),
                io.read_packets(&mut packets, &mut outcomes),
            )
            .await
            .is_err()
        );
        assert!(outcomes.is_empty());
        peer.send(&IPV4).unwrap();
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(packets[0], IPV4);
    }

    #[tokio::test]
    async fn batch_read_preserves_consumed_prefix_on_eof() {
        let (host, mut peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::RawIp,
        )
        .unwrap();
        peer.write_all(&IPV4).unwrap();
        drop(peer);
        let mut packets = [Vec::new(), Vec::new()];
        let mut outcomes = Vec::new();
        assert!(matches!(
            io.read_packets(&mut packets, &mut outcomes).await,
            Err(VoleError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        assert_eq!(packets[0], IPV4);
    }

    #[tokio::test]
    async fn batch_write_keeps_packet_boundaries_and_isolates_invalid_packets() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::RawIp,
        )
        .unwrap();
        let oversized = vec![0x45; TUN_MTU + 1];
        let mut outcomes = Vec::new();
        io.write_packets(&[&IPV4, &[0x70], &oversized, &IPV6], &mut outcomes)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 4);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        assert!(matches!(outcomes[1], Err(VoleError::InvalidPacket(_))));
        assert!(matches!(outcomes[2], Err(VoleError::InvalidPacket(_))));
        assert_eq!(outcomes[3].as_ref().unwrap(), &IpVersion::V6);
        let mut received = [0_u8; TUN_MTU];
        for packet in [&IPV4[..], &IPV6[..]] {
            let size = peer.recv(&mut received).unwrap();
            assert_eq!(&received[..size], packet);
        }
        assert_eq!(
            peer.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn tun_rs_drop_closes_only_duplicate_and_preserves_host_flags() {
        let (mut host, mut peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        // SAFETY: host remains open for both flag reads.
        let before = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::RawIp).unwrap();
        let duplicate = io.device.get_ref().as_raw_fd();
        assert_ne!(duplicate, host.as_raw_fd());
        // SAFETY: both descriptors are open while the adapter is alive.
        let constructed_flags = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(constructed_flags, before);
        // SAFETY: the duplicate is owned by the live adapter.
        let descriptor_flags = unsafe { libc::fcntl(duplicate, libc::F_GETFD) };
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        drop(io);
        // SAFETY: the adapter owns only the duplicate; host remains open.
        let after = unsafe { libc::fcntl(host.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(after, before);

        host.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        peer.set_nonblocking(true).unwrap();
        drop(host);
        // EOF checks release without racing reuse of the numeric duplicate fd.
        assert_eq!(peer.read(&mut bytes).unwrap(), 0);
    }

    #[tokio::test]
    async fn raw_ip_rejects_invalid_version_and_oversized_write() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::RawIp).unwrap();

        peer.send(&[0x70]).unwrap();
        assert!(matches!(
            io.read_packet(&mut Vec::new()).await,
            Err(VoleError::InvalidPacket("unsupported IP version"))
        ));
        assert!(matches!(
            io.write_packet(&vec![0x45; TUN_MTU + 1]).await,
            Err(VoleError::InvalidPacket(
                "TUN packet exceeds configured MTU"
            ))
        ));
    }

    #[tokio::test]
    async fn zero_length_read_is_tun_eof() {
        let (host, peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::RawIp).unwrap();
        drop(peer);

        let error = io.read_packet(&mut Vec::new()).await.unwrap_err();
        assert!(matches!(
            error,
            VoleError::Io(ref error) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_full_packet_queue_waits_without_losing_or_replaying_a_packet() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::Utun,
        )
        .unwrap();
        let mut frame = 2_u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&IPV4);
        // Cache a writable readiness observation before the peer queue fills.
        // Starting with an already-full fd would only test the initial wait.
        io.write_packet(&IPV4).await.unwrap();
        let mut queued = 1;
        loop {
            match host.send(&frame) {
                Ok(_) => {
                    queued += 1;
                    assert!(queued < 65536);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected local queue error: {error}"),
            }
        }
        let write = io.write_packet(&IPV6);
        tokio::pin!(write);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), &mut write)
                .await
                .is_err(),
            "a full local packet queue must apply backpressure, not terminate TUN"
        );
        let mut received = [0; 64];
        assert_eq!(peer.recv(&mut received).unwrap(), frame.len());
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut write)
                .await
                .unwrap()
                .unwrap(),
            IpVersion::V6
        );
        for _ in 1..queued {
            assert_eq!(peer.recv(&mut received).unwrap(), frame.len());
            assert_eq!(&received[..frame.len()], frame);
        }
        assert_eq!(peer.recv(&mut received).unwrap(), IPV6.len() + 4);
        assert_eq!(&received[..4], 30_u32.to_be_bytes());
        assert_eq!(&received[4..IPV6.len() + 4], IPV6);
        assert_eq!(
            peer.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // Cancelling a blocked write must not leave a retry task behind.
        io.write_packet(&IPV4).await.unwrap();
        while host.send(&frame).is_ok() {}
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), io.write_packet(&IPV6))
                .await
                .is_err()
        );
        while let Ok(size) = peer.recv(&mut received) {
            assert_eq!(&received[..size], frame);
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert_eq!(
            peer.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn cancelling_batch_write_preserves_accepted_prefix_without_replaying_it() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::Utun,
        )
        .unwrap();
        let mut frame = 2_u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&IPV4);
        io.write_packet(&IPV4).await.unwrap();
        let mut queued = 1;
        loop {
            match host.send(&frame) {
                Ok(_) => {
                    queued += 1;
                    assert!(queued < 65536);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected local queue error: {error}"),
            }
        }
        let mut received = [0_u8; 64];
        peer.recv(&mut received).unwrap();
        let mut outcomes = Vec::new();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                io.write_packets(&[&IPV4, &IPV6], &mut outcomes),
            )
            .await
            .is_err()
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        // One original frame was removed, and the first batch packet replaced
        // it. Cancelling the pending second packet leaves exactly this count.
        for _ in 0..queued {
            let size = peer.recv(&mut received).unwrap();
            assert_eq!(&received[..size], frame);
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert_eq!(
            peer.recv(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_batches_keep_each_packet_information_header_independent() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let io = TunRsIo::new_mock(
            TunFd::duplicate_mock(host.as_raw_fd()).unwrap(),
            TunFraming::Utun,
        )
        .unwrap();
        let mut outcomes = Vec::new();
        io.write_packets(&[&IPV4, &IPV6], &mut outcomes)
            .await
            .unwrap();
        let mut received = [0_u8; 64];
        for (packet, family) in [(&IPV4[..], 2_u32), (&IPV6[..], 30_u32)] {
            let size = peer.recv(&mut received).unwrap();
            assert_eq!(&received[..4], family.to_be_bytes());
            assert_eq!(&received[4..size], packet);
            peer.send(&received[..size]).unwrap();
        }
        let mut packets = [Vec::new(), Vec::new()];
        io.read_packets(&mut packets, &mut outcomes).await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].as_ref().unwrap(), &IpVersion::V4);
        assert_eq!(outcomes[1].as_ref().unwrap(), &IpVersion::V6);
        assert_eq!(packets[0], IPV4);
        assert_eq!(packets[1], IPV6);
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_write_adds_darwin_family_header_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::Utun).unwrap();

        for (packet, family, version) in [
            (&IPV4[..], 2_u32, IpVersion::V4),
            (&IPV6[..], 30_u32, IpVersion::V6),
        ] {
            assert_eq!(io.write_packet(packet).await.unwrap(), version);
            let mut received = [0_u8; 64];
            let size = peer.recv(&mut received).unwrap();
            assert_eq!(&received[..4], &family.to_be_bytes());
            assert_eq!(&received[4..size], packet);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn utun_read_strips_darwin_family_header_for_ipv4_and_ipv6() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = TunFd::duplicate_mock(host.as_raw_fd()).unwrap();
        let io = TunRsIo::new_mock(fd, TunFraming::Utun).unwrap();

        let mut packet = Vec::new();
        for (expected, family, version) in [
            (&IPV4[..], 2_u32, IpVersion::V4),
            (&IPV6[..], 30_u32, IpVersion::V6),
        ] {
            let mut frame = family.to_be_bytes().to_vec();
            frame.extend_from_slice(expected);
            peer.send(&frame).unwrap();
            assert_eq!(io.read_packet(&mut packet).await.unwrap(), version);
            assert_eq!(packet, expected);
        }
    }
}
