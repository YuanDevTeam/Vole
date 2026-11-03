#[cfg(all(
    feature = "invoke",
    any(target_os = "ios", target_os = "tvos", target_os = "macos")
))]
pub(crate) mod apple_logging;
#[cfg(all(feature = "tun", any(target_os = "linux", test)))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod linux_network;
#[cfg(all(target_os = "linux", feature = "tun"))]
mod linux_tun;
#[cfg(feature = "invoke")]
pub(crate) mod process_memory;
#[cfg(all(unix, feature = "tun"))]
mod tun_fd;
#[cfg(all(unix, feature = "tun"))]
mod tun_rs_io;
#[cfg(all(
    windows,
    feature = "tun",
    any(feature = "windows-wintun", feature = "windows-uwp")
))]
mod windows_io;
#[cfg(all(
    feature = "tun",
    any(
        test,
        all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
    )
))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_tun_io;
#[cfg(all(feature = "tun", any(test, all(windows, feature = "windows-wintun"))))]
#[cfg_attr(not(windows), allow(dead_code))]
mod windows_wintun_io;

/// Ready packets processed per turn; never wait to fill this batch.
#[cfg(feature = "tun")]
pub(crate) const TUN_PACKET_BATCH_SIZE: usize = 8;

#[cfg(all(unix, feature = "tun"))]
pub use tun_fd::TunFd;
#[cfg(all(unix, feature = "tun"))]
pub use tun_rs_io::TunRsIo as TunIo;
#[cfg(all(
    windows,
    feature = "tun",
    any(feature = "windows-wintun", feature = "windows-uwp")
))]
pub(crate) use windows_io::TunIo;
#[cfg(all(windows, feature = "tun", feature = "windows-uwp"))]
pub(crate) use windows_tun_io::{
    WindowsPacketAdapter, WindowsPacketStats, validate_packet_channel_config,
};
#[cfg(all(windows, feature = "tun", feature = "windows-wintun"))]
pub(crate) use windows_wintun_io::WindowsWintunIo;
