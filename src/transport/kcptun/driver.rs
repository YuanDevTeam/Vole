//! One bounded KCP core driven by caller-supplied, protected datagram IO.
use super::{crypto::PacketCrypt, fec::Fec};
use crate::{
    config::KcptunConfig,
    dispatch::{BoxStream, DatagramTransport},
    session::{Datagram, Destination},
};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
const QUEUE: usize = 128;
const CHUNK: usize = 16 * 1024;
#[derive(Clone)]
struct Output(Arc<Mutex<VecDeque<Vec<u8>>>>);
impl io::Write for Output {
    fn write(&mut self, wire: &[u8]) -> io::Result<usize> {
        let mut queue = self.0.lock().unwrap();
        // The KCP core retains unacknowledged segments. Dropping a full physical
        // queue is recoverable through its existing retransmission machinery.
        if queue.len() < QUEUE {
            queue.push_back(wire.to_vec());
        }
        Ok(wire.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn attach(
    mut transport: Box<dyn DatagramTransport>,
    peer: Destination,
    config: KcptunConfig,
    crypto: Arc<PacketCrypt>,
    cancel: CancellationToken,
) -> io::Result<(
    BoxStream,
    impl std::future::Future<Output = io::Result<()>> + Send,
)> {
    let mut fec = Fec::new(config.data_shards, config.parity_shards)?;
    let budget = transport.payload_budget(&peer);
    // MTU configures our transmission segmentation, not the peer's MTU.
    // kcp-go accepts incoming wire packets up to its independent 1500-byte
    // receive ceiling; an upstream envelope may narrow either direction.
    let mtu = usize::from(config.mtu).min(usize::from(budget.transmit()));
    let receive_limit = usize::from(budget.receive()).min(1500);
    let kcp_mtu = mtu
        .checked_sub(crypto.overhead() + fec.overhead())
        .filter(|n| *n >= 50)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let output = Output(Arc::new(Mutex::new(VecDeque::new())));
    let mut kcp = kcp::Kcp::new_stream(rand::random(), output.clone());
    kcp.set_mtu(kcp_mtu).map_err(io::Error::other)?;
    kcp.set_nodelay(
        config.nodelay,
        config.interval as i32,
        config.resend as i32,
        config.no_congestion,
    );
    let cap = (512 * 1024 / kcp_mtu).max(32) as u16;
    kcp.set_wndsize(config.send_window.min(cap), config.receive_window.min(cap));
    kcp.update(0).map_err(io::Error::other)?;
    let (stream, io) = tokio::io::duplex(CHUNK);
    let (mut upload, mut download) = tokio::io::split(io);
    let driver = async move {
        let result=async {
            let epoch=tokio::time::Instant::now();
            let mut timer=tokio::time::interval(std::time::Duration::from_millis(u64::from(config.interval)));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut upload_bytes=vec![0;CHUNK];
            let mut download_bytes=vec![0;CHUNK];
            let mut downloaded=0usize;let mut flushed=0usize;
            let mut pending_send:Option<crate::dispatch::OwnedDatagramSend>=None;
            let mut send_at=tokio::time::Instant::now();
            let mut wire_queue=VecDeque::new();
            // Direct's controlled UDP socket is opened by its first send.
            // Receiving before that reports an uninitialized association.
            let mut received_enabled=false;
            let mut final_upload=false;
            loop {
                // Copy at most one application chunk out of KCP. A slow reader
                // fills the fixed duplex and advertised receive window.
                if downloaded==flushed {
                    match kcp.recv(&mut download_bytes) {
                        Ok(n)=>{downloaded=n;flushed=0;},
                        Err(kcp::Error::RecvQueueEmpty|kcp::Error::ExpectingFragment)=>{},
                        Err(error)=>return Err(io::Error::other(error)),
                    }
                }
                let can_send=pending_send.is_none()&&(!wire_queue.is_empty()||!output.0.lock().unwrap().is_empty());
                tokio::select! {
                    ()=cancel.cancelled()=>return Ok(()),
                    sent=async {pending_send.as_mut().unwrap().as_mut().await},if pending_send.is_some()=>{sent.map_err(io::Error::other)?;pending_send.take();received_enabled=true;},
                    written=download.write(&download_bytes[flushed..downloaded]),if flushed<downloaded=>{let n=written?;if n==0{return Err(io::ErrorKind::WriteZero.into());}flushed+=n;},
                    received=transport.receive(),if received_enabled=>{
                        let received=received.map_err(io::Error::other)?;
                        if received.remote!=peer || received.payload.len()>receive_limit{continue;}
                        if let Some(wire)=crypto.open(&received.payload) {
                            for packet in fec.decode(&wire)? {
                                if packet.len()>=24&&kcp::get_conv(&packet)==kcp.conv() {
                                    let _=kcp.input(&packet);
                                }
                            }
                            if config.ack_nodelay {kcp.flush_ack().map_err(io::Error::other)?;}
                        }
                    },
                    uploaded=upload.read(&mut upload_bytes),if !final_upload&&kcp.wait_snd()<usize::from(config.send_window.min(cap))=>{
                        let n=uploaded?;
                        if n==0{final_upload=true;}else{kcp.send(&upload_bytes[..n]).map_err(io::Error::other)?;kcp.flush().map_err(io::Error::other)?;}
                    },
                    _=timer.tick()=>{kcp.update(epoch.elapsed().as_millis()as u32).map_err(io::Error::other)?;if kcp.is_dead_link(){return Err(io::ErrorKind::TimedOut.into());}},
                    _=tokio::time::sleep_until(send_at),if can_send=>{},
                }
                if pending_send.is_none() && tokio::time::Instant::now() >= send_at {
                    if wire_queue.is_empty() {
                        let packet=output.0.lock().unwrap().pop_front();
                        if let Some(packet)=packet {
                            for frame in fec.encode(&packet)? {wire_queue.push_back(crypto.seal(&frame)?);}
                        }
                    }
                    if let Some(wire)=wire_queue.pop_front() {
                        if config.rate_limit>0 {
                            send_at=send_at.max(tokio::time::Instant::now())+std::time::Duration::from_secs_f64(wire.len()as f64/f64::from(config.rate_limit));
                        }
                        let datagram=Datagram {remote:peer.clone(),payload:Bytes::from(wire),sniffed_domain:None};
                        match transport.send_owned(datagram) {
                            Ok(send)=>pending_send=Some(send),
                            Err(packet)=>{tokio::select!{biased;()=cancel.cancelled()=>return Ok(()),result=transport.send(packet)=>{result.map_err(io::Error::other)?;received_enabled=true;},}}
                        }
                    }
                }
                if final_upload&&kcp.wait_snd()==0 {return Ok(());}
            }
        }.await;
        // Drop any leased send before closing the exact supplied transport.
        let close = transport.close().await.map_err(io::Error::other);
        result.and(close)
    };
    Ok((Box::new(stream), driver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::DispatchError;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::mpsc;
    struct MemoryCarrier {
        sent: mpsc::Sender<Datagram>,
        received: mpsc::Receiver<Datagram>,
        closed: Arc<AtomicBool>,
        sent_once: bool,
    }
    #[async_trait::async_trait]
    impl DatagramTransport for MemoryCarrier {
        fn payload_budget(&self, _peer: &Destination) -> crate::dispatch::DatagramBudget {
            crate::dispatch::DatagramBudget::new(1350, 1500)
        }
        async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
            self.sent
                .send(packet)
                .await
                .map_err(|_| DispatchError::ConnectionRefused)?;
            self.sent_once = true;
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if !self.sent_once {
                return Err(DispatchError::Other(
                    "receive before controlled first send".into(),
                ));
            }
            self.received
                .recv()
                .await
                .ok_or(DispatchError::ConnectionRefused)
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.closed.store(true, Ordering::Release);
            Ok(())
        }
    }
    #[tokio::test]
    async fn controlled_kcp_memory_carrier_delivers_bidirectionally_and_joins_on_stop() {
        tokio::time::timeout(std::time::Duration::from_secs(3),async {
            let (sent,mut at_peer)=mpsc::channel::<Datagram>(32);let (from_peer,received)=mpsc::channel(32);
            let closed=Arc::new(AtomicBool::new(false));
            let carrier=Box::new(MemoryCarrier {sent,received,closed:closed.clone(),sent_once:false});
            let options=KcptunConfig {crypt:"null".into(),no_comp:true,data_shards:0,parity_shards:0,..Default::default()};
            let cancel=CancellationToken::new();let peer:Destination="127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap().into();
            let (mut stream,driver)=attach(carrier,peer.clone(),options,Arc::new(PacketCrypt::new("synthetic","null").unwrap()),cancel.clone()).unwrap();
            let driver=tokio::spawn(driver);let stop_peer=CancellationToken::new();let stopped=stop_peer.clone();
            let peer=tokio::spawn(async move {
                let first=at_peer.recv().await.unwrap();let output=Output(Arc::new(Mutex::new(VecDeque::new())));
                let mut server=kcp::Kcp::new_stream(kcp::get_conv(&first.payload),output.clone());// Deliberately use a larger peer transmission MTU than the client.
                server.set_mtu(1400).unwrap();server.set_nodelay(true,10,2,true);server.set_wndsize(128,512);server.update(0).unwrap();server.input(&first.payload).unwrap();
                let epoch=tokio::time::Instant::now();let mut timer=tokio::time::interval(std::time::Duration::from_millis(10));let mut buf=[0;CHUNK];
                loop {
                    tokio::select! {()=stopped.cancelled()=>break,packet=at_peer.recv()=>{let Some(packet)=packet else{break;};server.input(&packet.payload).unwrap();},_=timer.tick()=>{}}
                    while let Ok(n)=server.recv(&mut buf) {server.send(&buf[..n]).unwrap();}
                    server.update(epoch.elapsed().as_millis()as u32).unwrap();server.flush().unwrap();
                    loop {let wire=output.0.lock().unwrap().pop_front();let Some(wire)=wire else{break;};if from_peer.send(Datagram {remote:peer.clone(),payload:Bytes::from(wire),sniffed_domain:None}).await.is_err(){return;}}
                }
            });
            // Exercise the real lazy-UDP cold start before application bytes exist.
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            assert!(!driver.is_finished(),"cold driver polled receive before its first send");
            let payload=vec![7;32000];stream.write_all(&payload).await.unwrap();stream.flush().await.unwrap();let mut received=vec![0;payload.len()];stream.read_exact(&mut received).await.unwrap();assert_eq!(received,payload);
            cancel.cancel();driver.await.unwrap().unwrap();stop_peer.cancel();peer.await.unwrap();assert!(closed.load(Ordering::Acquire));
        }).await.unwrap();
    }
}
