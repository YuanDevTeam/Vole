#![cfg(all(
    feature = "stream-transport",
    feature = "quic-transport",
    feature = "outbound-vless",
    feature = "outbound-trojan",
    feature = "outbound-vmess"
))]
use std::collections::BTreeMap;

#[test]
fn registry_matches_live_production_constants_and_has_owned_boundary_cases() {
    #[cfg(feature = "interop-test")]
    let mut _case = vole::resources::case_events::Case::new(
        "FOUNDATIONS-LIMITS",
        "registry_matches_live_production_constants_and_has_owned_boundary_cases",
    );
    use vole::{ResourceLimits, dispatch, transport};
    let defaults = ResourceLimits::default();
    let expected = BTreeMap::from([
        ("tuic-quic-payload", vole::limits::TUIC_QUIC_PAYLOAD),
        ("tuic-control-readers", vole::limits::TUIC_CONTROL_READERS),
        ("tuic-send-window", vole::limits::TUIC_SEND_WINDOW),
        ("tuic-datagram-buffer", vole::limits::TUIC_DATAGRAM_BUFFER),
        ("tuic-udp-queue", vole::limits::TUIC_UDP_QUEUE),
        ("tuic-pending-packets", vole::limits::TUIC_PENDING_PACKETS),
        ("tuic-pending-bytes", vole::limits::TUIC_PENDING_BYTES),
        ("tuic-fin-grace", vole::limits::TUIC_FIN_GRACE_SECONDS),
        ("tuic-fragment-ttl", vole::limits::TUIC_FRAGMENT_TTL_SECONDS),
        (
            "shadowsocks-write-chunk",
            vole::limits::SHADOWSOCKS_WRITE_CHUNK,
        ),
        ("hy2-udp-payload", vole::limits::HY2_UDP_PAYLOAD),
        ("hy2-udp-queue", vole::limits::HY2_UDP_QUEUE),
        ("hy2-submission-queue", vole::limits::HY2_SUBMISSION_QUEUE),
        ("hy2-auth-sessions", vole::limits::HY2_AUTH_SESSIONS),
        ("hy2-pending-packets", vole::limits::HY2_PENDING_PACKETS),
        ("hy2-pending-bytes", vole::limits::HY2_PENDING_BYTES),
        ("hy2-fragment-ttl", vole::limits::HY2_FRAGMENT_TTL_SECONDS),
        ("hy2-path-retire", vole::limits::HY2_PATH_RETIRE_SECONDS),
        ("hy2-quic-payload", vole::limits::HY2_QUIC_PAYLOAD),
        ("hy2-uni-streams", vole::limits::HY2_UNI_STREAMS),
        ("hy2-send-window", vole::limits::HY2_SEND_WINDOW),
        (
            "hy2-datagram-send-buffer",
            vole::limits::HY2_DATAGRAM_SEND_BUFFER,
        ),
        (
            "hy2-datagram-receive-buffer",
            vole::limits::HY2_DATAGRAM_RECEIVE_BUFFER,
        ),
        ("hy2-auth-headers", vole::limits::HY2_AUTH_HEADERS),
        ("hy2-response-message", vole::limits::HY2_RESPONSE_MESSAGE),
        ("hy2-response-padding", vole::limits::HY2_RESPONSE_PADDING),
        ("vless-udp-frame", vole::limits::VLESS_UDP_FRAME_BYTES),
        ("vision-content", vole::limits::VISION_CONTENT_BYTES),
        ("vision-tls-record", vole::limits::VISION_TLS_RECORD_BYTES),
        ("vision-hello", vole::limits::VISION_HELLO_BYTES),
        ("grpc-idle", vole::limits::GRPC_IDLE_CONNECTIONS),
        ("grpc-ping-timeout", vole::limits::GRPC_PING_TIMEOUT_SECONDS),
        ("config-bytes", vole::config::MAX_CONFIG_BYTES),
        (
            "establish-timeout",
            vole::outbound::DEFAULT_ESTABLISH_TIMEOUT.as_millis() as usize,
        ),
        ("tls-buffer", defaults.tls_buffer_limit),
        (
            "tls-close",
            vole::security::CLOSE_NOTIFY_TIMEOUT.as_millis() as usize,
        ),
        (
            "tls-resumption",
            vole::security::TLS_RESUMPTION_SESSION_BUDGET,
        ),
        ("stream-chunk", transport::STREAM_CHUNK_BYTES),
        ("stream-buffer", transport::STREAM_BUFFER_BYTES),
        ("http-head", transport::HTTP_HEAD_BYTES),
        ("http-headers", transport::HTTP_HEADER_COUNT),
        ("ws-early-data", transport::MAX_EARLY_DATA_BYTES),
        (
            "trojan-udp-payload",
            usize::from(vole::outbound::trojan::MAX_DATAGRAM_PAYLOAD),
        ),
        ("xudp-metadata", vole::xudp::MAX_METADATA_LENGTH),
        ("vmess-body-wire", vole::outbound::vmess::MAX_BODY_WIRE),
        ("vmess-write-chunk", vole::outbound::vmess::WRITE_CHUNK),
        ("vmess-datagram", vole::outbound::vmess::MAX_PACKET_BYTES),
        ("io-poll", vole::limits::IO_POLL_BUDGET),
        ("quic-queue", transport::quic::QUEUE_LIMIT),
        (
            "quic-close",
            transport::quic::CLOSE_TIMEOUT.as_millis() as usize,
        ),
        (
            "quic-minimum",
            usize::from(dispatch::QUIC_MIN_PAYLOAD_BYTES),
        ),
        (
            "resolution-depth",
            vole::dns::resolution::MAX_RESOLUTION_DEPTH,
        ),
        ("packet-queue", defaults.packet_queue_capacity),
        ("event-queue", defaults.event_queue_capacity),
        ("udp-payload", defaults.max_datagram_size),
        ("tun-packet", defaults.tun_max_datagram_size),
        ("tcp-buffer", defaults.tcp_buffer_per_direction),
        ("dns-cache", defaults.dns_address_cache_entries),
        ("dns-hints", defaults.dns_redir_host_entries),
        (
            "tun-udp-association",
            defaults.tun_udp_association_queue_capacity,
        ),
        ("tun-udp-response", defaults.tun_udp_response_queue_capacity),
        ("tun-dns-response", defaults.tun_dns_response_queue_capacity),
        ("xhttp-send", defaults.xhttp_send_buffer_size),
        ("xhttp-upload", defaults.xhttp_upload_chunk_size),
        (
            "xhttp-custom-header-bytes",
            vole::limits::XHTTP_CUSTOM_HEADER_BYTES,
        ),
        ("xhttp-custom-headers", vole::limits::XHTTP_CUSTOM_HEADERS),
        ("xhttp-padding", vole::limits::XHTTP_PADDING_BYTES),
        ("xhttp-post", vole::limits::XHTTP_POST_BYTES),
        ("xhttp-packet-batch", vole::limits::XHTTP_PACKET_BATCH_BYTES),
        ("xhttp-request-bytes", vole::limits::XHTTP_REQUEST_BYTES),
        ("xhttp-request-headers", vole::limits::XHTTP_REQUEST_HEADERS),
        ("xhttp-idle-entries", vole::limits::XHTTP_IDLE_ENTRIES),
        ("xhttp-idle-h1", vole::limits::XHTTP_IDLE_H1_CONNECTIONS),
        ("xhttp-body-queue", vole::limits::XHTTP_BODY_QUEUE),
        ("xhttp-body-chunk", vole::limits::XHTTP_BODY_CHUNK),
        ("xhttp-h3-uni-streams", vole::limits::XHTTP_H3_UNI_STREAMS),
        (
            "xhttp-h3-stream-window",
            vole::limits::XHTTP_H3_STREAM_WINDOW,
        ),
        (
            "xhttp-h3-connection-window",
            vole::limits::XHTTP_H3_CONNECTION_WINDOW,
        ),
        ("xhttp-h3-send-window", vole::limits::XHTTP_H3_SEND_WINDOW),
        ("sing-mux-idle", vole::limits::SING_MUX_IDLE_CONNECTIONS),
        (
            "sing-mux-command-queue",
            vole::limits::SING_MUX_COMMAND_QUEUE,
        ),
        ("sing-mux-chunk", vole::limits::SING_MUX_CHUNK),
        ("smux-receive-queue", vole::limits::SMUX_RECEIVE_QUEUE),
        (
            "yamux-admissions",
            vole::limits::YAMUX_CONNECTION_ADMISSIONS,
        ),
        ("yamux-window", vole::limits::YAMUX_CONNECTION_WINDOW),
    ]);
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("protocols/limits.json")).unwrap();
    let rows = registry["limits"].as_array().unwrap();
    assert_eq!(rows.len(), expected.len());
    let mut actual = BTreeMap::new();
    for row in rows {
        let id = row["id"].as_str().unwrap();
        assert!(
            actual
                .insert(id, row["value"].as_u64().unwrap() as usize)
                .is_none()
        );
        for key in ["unit", "owner", "saturation", "cancellation"] {
            assert!(!row[key].as_str().unwrap().is_empty());
        }
        assert!(!row["boundary_cases"].as_array().unwrap().is_empty());
    }
    assert_eq!(actual, expected);
}
