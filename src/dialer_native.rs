//! Linux plain socket setup under the existing initialization owner. No callback
//! or arbitrary initialization closure is executed by this admission path.
use super::*;

#[must_use = "keep native socket admission until setup has completed or failed"]
pub(super) struct NativeSocketAdmission {
    // Declaration order preserves the blocking path's release order: first
    // observation, then tracker token, finally capacity for the next job.
    _observation: crate::resources::observation::Guard,
    _token: tokio_util::task::task_tracker::TaskTrackerToken,
    _permit: tokio::sync::OwnedSemaphorePermit,
    cancellation: CancellationToken,
}

impl NativeSocketAdmission {
    pub(super) fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            Err(socket_initialization_cancelled())
        } else {
            Ok(())
        }
    }
}

impl SocketInitialization {
    pub(super) async fn admit_native_socket(&self) -> io::Result<NativeSocketAdmission> {
        let permit = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(socket_initialization_cancelled()),
            permit = Arc::clone(&self.submissions).acquire_owned() => {
                permit.map_err(|_| socket_initialization_cancelled())?
            }
        };
        let token = {
            let closed = self
                .closed
                .lock()
                .map_err(|_| io::Error::other("socket initialization lock is poisoned"))?;
            if *closed {
                return Err(socket_initialization_cancelled());
            }
            self.tasks.token()
        };
        let admission = NativeSocketAdmission {
            _observation: track(ResourceKind::Task),
            _token: token,
            _permit: permit,
            cancellation: self.cancellation.clone(),
        };
        admission.check()?;
        Ok(admission)
    }
}

impl Dialer {
    pub(super) fn permits_plain_native_socket_setup(&self) -> bool {
        if self.tfo
            || self.mptcp
            || self.protector.is_some()
            || self.source_binding.is_some()
            || self.egress.interface.is_some()
            || self.dns_binding.is_some()
        {
            return false;
        }
        #[cfg(feature = "tun")]
        if self
            .linux_policy
            .as_ref()
            .is_some_and(|policy| policy.detects_interface())
        {
            return false;
        }
        true
    }

    pub(super) async fn prepare_plain_native_tcp_socket(
        &self,
        address: SocketAddr,
    ) -> io::Result<(TcpSocket, crate::resources::observation::Guard, SocketAddr)> {
        let address = self.connected_address(address)?;
        self.validate_egress()?;
        let source_address = self.source_address_for(address)?;
        let admission = self.initialization.admit_native_socket().await?;
        admission.check()?;
        let socket = new_plain_tcp_socket(address.is_ipv6())?;
        let (socket, guard) =
            self.configure_tcp_socket(socket, address, source_address, &|| admission.check())?;
        admission.check()?;
        Ok((socket, guard, address))
    }

    pub(super) async fn bind_plain_native_udp_socket(
        &self,
        destination: SocketAddr,
        bind_address: SocketAddr,
        options: UdpSocketOptions,
    ) -> io::Result<PhysicalDatagram> {
        let admission = self.initialization.admit_native_socket().await?;
        admission.check()?;
        let (socket, guard) =
            self.configure_udp_socket(destination, bind_address, options, &|| admission.check())?;
        let socket = UdpSocket::from_std(socket)?;
        admission.check()?;
        Ok(ObservedIo::with_guard(socket, guard))
    }
}
