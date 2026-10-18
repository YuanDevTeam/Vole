//! Bounded subscription URI conversion into the ordinary strict node schema.
//! Wire and transport semantics remain owned by configuration and outbounds.
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Map, Value, json};
use url::{Host, Url};

use super::age_provider::DecodeControl;
use crate::{Result, VoleError, config::MAX_CONFIG_BYTES};

const CONVERSION_BUDGET: usize = MAX_CONFIG_BYTES * 4;
const MAX_URI_LINE_BYTES: usize = 64 * 1024;
// Reserve scratch before URL/query parsing, decoded credentials, JSON/YAML
// conversion and cloned transport options. It is released after each line;
// retained nodes and name indexes remain charged separately. This deliberately
// overestimates small-token trees rather than measuring allocator internals.
fn scratch_allowance(bytes: usize) -> Result<usize> {
    bytes
        .checked_mul(256)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(invalid)
}

fn invalid() -> VoleError {
    VoleError::InvalidConfig("invalid or unsupported proxy subscription content".into())
}

fn decode64(input: &[u8], url_safe: bool) -> Option<Vec<u8>> {
    if input.len() > MAX_CONFIG_BYTES
        || !input.iter().all(|c| {
            c.is_ascii_alphanumeric() || b"+/=\r\n".contains(c) || url_safe && b"-_".contains(c)
        })
    {
        return None;
    }
    let clean: Cow<'_, [u8]> = if input.contains(&b'\r') || input.contains(&b'\n') {
        Cow::Owned(
            input
                .iter()
                .copied()
                .filter(|b| !matches!(b, b'\r' | b'\n'))
                .collect(),
        )
    } else {
        Cow::Borrowed(input)
    };
    STANDARD_NO_PAD
        .decode(&clean)
        .or_else(|_| STANDARD.decode(&clean))
        .or_else(|error| {
            if url_safe {
                URL_SAFE_NO_PAD
                    .decode(&clean)
                    .or_else(|_| URL_SAFE.decode(&clean))
            } else {
                Err(error)
            }
        })
        .ok()
}

fn unescape(input: &str) -> Result<String> {
    let mut output = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let a = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(invalid)?;
            let b = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(invalid)?;
            output.push((a * 16 + b) as u8);
        } else {
            output.push(byte);
        }
    }
    String::from_utf8(output).map_err(|_| invalid())
}

struct Link {
    url: Url,
    port: Option<u16>,
    query: BTreeMap<String, Vec<String>>,
}
impl Link {
    fn parse(line: &str, budget: &mut usize) -> Result<Self> {
        let mut url = Url::parse(line).map_err(|_| invalid())?;
        if url.scheme() == "vless" && url.port().is_none() {
            if let Some(decoded) = url
                .host_str()
                .and_then(|host| decode64(host.as_bytes(), false))
            {
                let endpoint = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
                let endpoint = Url::parse(&format!("vless://{endpoint}")).map_err(|_| invalid())?;
                url.set_host(endpoint.host_str()).map_err(|_| invalid())?;
                url.set_port(endpoint.port()).map_err(|_| invalid())?;
            }
        }
        let mut query = BTreeMap::<String, Vec<String>>::new();
        for (key, value) in url.query_pairs() {
            *budget = budget
                .checked_sub(128 + key.len() + value.len())
                .ok_or_else(invalid)?;
            query
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        // Url canonicalizes explicit HTTP(S) default ports away. The subscription
        // parser must retain that valid explicit endpoint without inventing ports.
        let authority = line
            .split_once("://")
            .map(|(_, suffix)| suffix)
            .and_then(|suffix| suffix.split(['/', '?', '#']).next())
            .unwrap_or_default();
        let port = url.port().or_else(|| {
            authority
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
        });
        Ok(Self { url, port, query })
    }
    fn get(&self, name: &str) -> &str {
        self.query
            .get(name)
            .and_then(|v| v.first())
            .map_or("", String::as_str)
    }
    fn user(&self) -> Result<String> {
        unescape(self.url.username())
    }
    fn password(&self) -> Result<Option<String>> {
        self.url.password().map(unescape).transpose()
    }
    fn name(&self) -> Result<String> {
        unescape(self.url.fragment().unwrap_or_default())
    }
    fn host(&self) -> Result<String> {
        let host = match self.url.host().ok_or_else(invalid)? {
            Host::Domain(host) => host.to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        if host.is_empty() {
            return Err(invalid());
        }
        Ok(host)
    }
    fn base(&self, kind: &str, default_port: Option<u16>) -> Result<Map<String, Value>> {
        let host = self.host()?;
        let port = self
            .port
            .or(default_port)
            .filter(|port| *port > 0)
            .ok_or_else(invalid)?;
        let name = self.name()?;
        Ok(json!({"name": if name.is_empty() { format!("{host}:{port}") } else { name }, "type":kind, "server":host, "port":port}).as_object().unwrap().clone())
    }
}

fn copy_query(node: &mut Map<String, Value>, link: &Link, fields: &[(&str, &str)]) {
    for (source, target) in fields {
        let value = link.get(source);
        if !value.is_empty() {
            node.insert((*target).into(), json!(value));
        }
    }
}
fn alpn(node: &mut Map<String, Value>, value: &str) {
    if !value.is_empty() {
        node.insert("alpn".into(), json!(value.split(',').collect::<Vec<_>>()));
    }
}
fn boolean(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

fn transport(
    node: &mut Map<String, Value>,
    link: &Link,
    kind: &str,
    budget: &mut usize,
) -> Result<()> {
    let mut network = link.get("type").to_ascii_lowercase();
    if network.is_empty() {
        network = "tcp".into();
    }
    if network == "tcp" && link.get("headerType").eq_ignore_ascii_case("http") {
        network = "http".into();
    } else if network == "http" && kind != "trojan" {
        network = "h2".into();
    }
    let path = if link.get("path").is_empty() {
        "/"
    } else {
        link.get("path")
    };
    match network.as_str() {
        "tcp" => {}
        "http" => {
            let mut options = json!({"path":[path], "headers":{}});
            if !link.get("host").is_empty() {
                options["headers"]["Host"] = json!([link.get("host")]);
            }
            if !link.get("method").is_empty() {
                options["method"] = json!(link.get("method"));
            }
            node.insert("http-opts".into(), options);
        }
        "h2" => {
            let mut options = json!({"path":path});
            if !link.get("host").is_empty() {
                options["host"] = json!([link.get("host")]);
            }
            node.insert("h2-opts".into(), options);
        }
        "ws" | "httpupgrade" => {
            let mut options = json!({"path":path,"headers":{}});
            if !link.get("host").is_empty() {
                options["headers"]["Host"] = json!(link.get("host"));
            }
            if network == "httpupgrade" {
                options["v2ray-http-upgrade"] = json!(true);
                options["v2ray-http-upgrade-fast-open"] = json!(!link.get("ed").is_empty());
                network = "ws".into();
            } else if !link.get("ed").is_empty() {
                options["max-early-data"] =
                    json!(link.get("ed").parse::<u16>().map_err(|_| invalid())?);
                options["early-data-header-name"] = json!("Sec-WebSocket-Protocol");
            }
            if !link.get("eh").is_empty() {
                options["early-data-header-name"] = json!(link.get("eh"));
            }
            node.insert("ws-opts".into(), options);
        }
        "grpc" => {
            node.insert(
                "grpc-opts".into(),
                json!({"grpc-service-name":link.get("serviceName")}),
            );
        }
        "xhttp" if kind == "vless" => {
            let mut options = Map::new();
            copy_query(
                &mut options,
                link,
                &[("path", "path"), ("host", "host"), ("mode", "mode")],
            );
            if !link.get("extra").is_empty() {
                let extra = parse_json(link.get("extra").as_bytes(), budget)?;
                xhttp_extra(&mut options, extra.as_object().ok_or_else(invalid)?)?;
            }
            node.insert("xhttp-opts".into(), Value::Object(options));
        }
        _ => return Err(invalid()),
    }
    node.insert("network".into(), json!(network));
    Ok(())
}

fn reuse(source: &Map<String, Value>) -> Map<String, Value> {
    let mut options = Map::new();
    for (source_key, target) in [
        ("maxConnections", "max-connections"),
        ("maxConcurrency", "max-concurrency"),
        ("cMaxReuseTimes", "c-max-reuse-times"),
        ("hMaxRequestTimes", "h-max-request-times"),
        ("hMaxReusableSecs", "h-max-reusable-secs"),
    ] {
        if let Some(value) = source.get(source_key) {
            if value.is_string() || value.is_i64() || value.is_u64() {
                options.insert(
                    target.into(),
                    json!(
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    ),
                );
            }
        }
    }
    if let Some(value) = source.get("hKeepAlivePeriod") {
        options.insert("h-keep-alive-period".into(), value.clone());
    }
    options
}
fn xhttp_extra(options: &mut Map<String, Value>, extra: &Map<String, Value>) -> Result<()> {
    for (source, target) in [
        ("headers", "headers"),
        ("noGRPCHeader", "no-grpc-header"),
        ("xPaddingBytes", "x-padding-bytes"),
        ("xPaddingObfsMode", "x-padding-obfs-mode"),
        ("xPaddingKey", "x-padding-key"),
        ("xPaddingHeader", "x-padding-header"),
        ("xPaddingPlacement", "x-padding-placement"),
        ("xPaddingMethod", "x-padding-method"),
        ("uplinkHTTPMethod", "uplink-http-method"),
        ("sessionIDPlacement", "session-placement"),
        ("sessionPlacement", "session-placement"),
        ("sessionIDKey", "session-key"),
        ("sessionKey", "session-key"),
        ("sessionIDTable", "session-table"),
        ("sessionIDLength", "session-length"),
        ("seqPlacement", "seq-placement"),
        ("seqKey", "seq-key"),
        ("uplinkDataPlacement", "uplink-data-placement"),
        ("uplinkDataKey", "uplink-data-key"),
        ("uplinkChunkSize", "uplink-chunk-size"),
        ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
        ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
    ] {
        if let Some(value) = extra.get(source) {
            options.entry(target).or_insert_with(|| value.clone());
        }
    }
    if let Some(length) = extra.get("sessionIDLength").and_then(Value::as_i64) {
        options.insert("session-length".into(), json!(length.to_string()));
    }
    if let Some(xmux) = extra.get("xmux").and_then(Value::as_object) {
        options.insert("reuse-settings".into(), Value::Object(reuse(xmux)));
    }
    if let Some(download) = extra.get("downloadSettings").and_then(Value::as_object) {
        let mut result = Map::new();
        for (source, target) in [("address", "server"), ("port", "port")] {
            if let Some(value) = download.get(source) {
                result.insert(target.into(), value.clone());
            }
        }
        let security = download
            .get("security")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(security, "tls" | "reality") {
            result.insert("tls".into(), json!(true));
            if let Some(tls) = download.get("tlsSettings").and_then(Value::as_object) {
                for (source, target) in [
                    ("serverName", "servername"),
                    ("fingerprint", "client-fingerprint"),
                    ("alpn", "alpn"),
                    ("allowInsecure", "skip-cert-verify"),
                ] {
                    if let Some(value) = tls.get(source) {
                        result.insert(target.into(), value.clone());
                    }
                }
            }
            if security == "reality" {
                if let Some(reality) = download.get("realitySettings").and_then(Value::as_object) {
                    let mut settings = Map::new();
                    for (source, target) in [("publicKey", "public-key"), ("shortId", "short-id")] {
                        if let Some(value) = reality.get(source) {
                            settings.insert(target.into(), value.clone());
                        }
                    }
                    result.insert("reality-opts".into(), Value::Object(settings));
                }
            }
        }
        if let Some(xhttp) = download.get("xhttpSettings").and_then(Value::as_object) {
            for field in ["path", "host", "headers"] {
                if let Some(value) = xhttp.get(field) {
                    result.insert(field.into(), value.clone());
                }
            }
            if let Some(xmux) = xhttp
                .get("extra")
                .and_then(|v| v.get("xmux"))
                .and_then(Value::as_object)
            {
                result.insert("reuse-settings".into(), Value::Object(reuse(xmux)));
            }
        }
        if !result.is_empty() {
            options.insert("download-settings".into(), Value::Object(result));
        }
    }
    Ok(())
}

fn v_share(link: &Link, kind: &str, budget: &mut usize) -> Result<Map<String, Value>> {
    let mut node = link.base(kind, None)?;
    node.insert("uuid".into(), json!(link.user()?));
    node.insert("udp".into(), json!(true));
    let security = link.get("security").to_ascii_lowercase();
    if security.ends_with("tls") || security == "reality" {
        node.insert("tls".into(), json!(true));
        node.insert(
            "client-fingerprint".into(),
            json!(if link.get("fp").is_empty() {
                "chrome"
            } else {
                link.get("fp")
            }),
        );
        alpn(&mut node, link.get("alpn"));
        copy_query(&mut node, link, &[("pcs", "fingerprint")]);
    }
    copy_query(&mut node, link, &[("sni", "servername")]);
    if !link.get("pbk").is_empty() {
        let mut reality = json!({"public-key":link.get("pbk"),"short-id":link.get("sid")});
        if !link.get("support-x25519mlkem768").is_empty() {
            reality["support-x25519mlkem768"] = json!(boolean(link.get("support-x25519mlkem768")));
        }
        node.insert("reality-opts".into(), reality);
    }
    let packet = match link.get("packetEncoding") {
        "none" => {
            if kind == "vless" {
                "none"
            } else {
                ""
            }
        }
        "packet" => "packetaddr",
        _ => "xudp",
    };
    node.insert("packet-encoding".into(), json!(packet));
    if kind == "vmess" {
        node.insert("alterId".into(), json!(0));
        node.insert(
            "cipher".into(),
            json!(if link.get("encryption").is_empty() {
                "auto"
            } else {
                link.get("encryption")
            }),
        );
    } else {
        copy_query(
            &mut node,
            link,
            &[("flow", "flow"), ("encryption", "encryption")],
        );
        if let Some(flow) = node.get_mut("flow") {
            *flow = json!(link.get("flow").to_ascii_lowercase());
        }
    }
    transport(&mut node, link, kind, budget)?;
    Ok(node)
}

fn vmess_json(bytes: &[u8], budget: &mut usize) -> Result<Map<String, Value>> {
    let values = parse_json(bytes, budget)?;
    let values = values.as_object().ok_or_else(invalid)?;
    let text = |key: &str| values.get(key).and_then(Value::as_str).unwrap_or_default();
    let number = |key: &str| -> Result<u64> {
        values
            .get(key)
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
            .ok_or_else(invalid)
    };
    let mut node = json!({"name":text("ps"),"type":"vmess","server":text("add"),"port":number("port")?,"uuid":text("id"),"alterId":if values.contains_key("aid") { number("aid")? } else { 0 },"udp":true,"packet-encoding":"xudp","cipher":if text("scy").is_empty() { "auto" } else { text("scy") },"tls":text("tls").to_ascii_lowercase().ends_with("tls")}).as_object().unwrap().clone();
    if !text("sni").is_empty() {
        node.insert("servername".into(), json!(text("sni")));
    }
    if node["tls"] == true {
        alpn(&mut node, text("alpn"));
    }
    let mut link = Link {
        url: Url::parse("vmess://placeholder:1").unwrap(),
        port: Some(1),
        query: BTreeMap::new(),
    };
    for (source, target) in [("net", "type"), ("host", "host"), ("path", "path")] {
        if !text(source).is_empty() {
            link.query.insert(target.into(), vec![text(source).into()]);
        }
    }
    // v2rayN encodes HTTP camouflage separately from its transport name.
    if text("type") == "http" {
        link.query.insert("type".into(), vec!["tcp".into()]);
        link.query.insert("headerType".into(), vec!["http".into()]);
    }
    if matches!(link.get("type"), "ws" | "httpupgrade") && !link.get("path").is_empty() {
        let mut path = Url::parse("https://placeholder")
            .unwrap()
            .join(link.get("path"))
            .map_err(|_| invalid())?;
        let mut retained = Vec::new();
        for (key, value) in path.query_pairs() {
            if matches!(key.as_ref(), "ed" | "eh") {
                link.query
                    .entry(key.into_owned())
                    .or_insert_with(|| vec![value.into_owned()]);
            } else {
                retained.push((key.into_owned(), value.into_owned()));
            }
        }
        path.set_query(None);
        if !retained.is_empty() {
            path.query_pairs_mut().extend_pairs(retained);
        }
        let mut result = path.path().to_owned();
        if let Some(query) = path.query() {
            result.push('?');
            result.push_str(query);
        }
        link.query.insert("path".into(), vec![result]);
    }
    transport(&mut node, &link, "vmess", budget)?;
    Ok(node)
}

fn shadowsocks(line: &str, budget: &mut usize) -> Result<Map<String, Value>> {
    let mut link = Link::parse(line, budget)?;
    if link.url.port().is_none() {
        let body = line
            .split_once("://")
            .ok_or_else(invalid)?
            .1
            .split(['#', '?'])
            .next()
            .unwrap();
        let decoded = decode64(body.as_bytes(), false).ok_or_else(invalid)?;
        let content = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
        let mut parsed = Link::parse(&format!("ss://{content}"), budget)?;
        parsed.url.set_fragment(link.url.fragment());
        parsed.query = link.query;
        link = parsed;
    }
    let mut node = link.base("ss", None)?;
    let (cipher, password) = if let Some(password) = link.password()? {
        (link.user()?, password)
    } else {
        let decoded = decode64(link.user()?.as_bytes(), true).ok_or_else(invalid)?;
        let text = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
        let (cipher, password) = text.split_once(':').ok_or_else(invalid)?;
        (cipher.into(), password.into())
    };
    if !matches!(
        cipher.as_str(),
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305"
    ) || !link.get("plugin").is_empty()
    {
        return Err(invalid());
    }
    node.insert("cipher".into(), json!(cipher));
    node.insert("password".into(), json!(password));
    node.insert("udp".into(), json!(true));
    if link.get("udp-over-tcp") == "true" || link.get("uot") == "1" {
        node.insert("udp-over-tcp".into(), json!(true));
        node.insert("udp-over-tcp-version".into(), json!(2));
    }
    Ok(node)
}

fn convert(line: &str, scheme: &str, parser: &mut Parser<'_>) -> Result<()> {
    if scheme == "vmess" {
        let body = line.split_once("://").ok_or_else(invalid)?.1;
        if let Some(decoded) = decode64(body.as_bytes(), false) {
            let node = vmess_json(&decoded, &mut parser.budget)?;
            return parser.push(node);
        }
    }
    if scheme == "ss" {
        let node = shadowsocks(line, &mut parser.budget)?;
        return parser.push(node);
    }
    let mut normalized = line.to_owned();
    let mut hopping = None;
    if matches!(scheme, "hysteria2" | "hy2") {
        let offset = line.find("://").ok_or_else(invalid)? + 3;
        let end = line[offset..]
            .find(['/', '?', '#'])
            .map_or(line.len(), |n| offset + n);
        let authority = &line[offset..end];
        let (userinfo, authority) = authority
            .rsplit_once('@')
            .map_or(("", authority), |(user, host)| {
                (&line[offset..offset + user.len() + 1], host)
            });
        if !authority.contains(']') {
            if let Some((host, ports)) = authority.rsplit_once(':') {
                if ports.contains([',', '-']) {
                    let first = ports.split([',', '-']).next().unwrap();
                    if first.is_empty() {
                        return Err(invalid());
                    }
                    normalized = format!(
                        "{}{}{}:{}{}",
                        &line[..offset],
                        userinfo,
                        host,
                        first,
                        &line[end..]
                    );
                    hopping = Some(ports.to_owned());
                }
            }
        }
    }
    let link = Link::parse(&normalized, &mut parser.budget)?;
    if matches!(scheme, "vless" | "vmess") {
        let node = v_share(&link, scheme, &mut parser.budget)?;
        return parser.push(node);
    }
    if scheme == "mierus" {
        let ports = link.query.get("port").ok_or_else(invalid)?;
        let protocols = link
            .query
            .get("protocol")
            .filter(|v| v.len() == ports.len())
            .ok_or_else(invalid)?;
        let host = link.host()?;
        let name = link.name()?;
        let name = if !name.is_empty() {
            name.as_str()
        } else if !link.get("profile").is_empty() {
            link.get("profile")
        } else {
            &host
        };
        for (port, protocol) in ports.iter().zip(protocols) {
            let mut node = json!({"name":format!("{name}:{port}/{protocol}"),"type":"mieru","server":host,"username":link.user()?,"password":link.password()?.unwrap_or_default(),"transport":protocol,"udp":true}).as_object().unwrap().clone();
            if port.contains('-') {
                node.insert("port-range".into(), json!(port));
            } else {
                node.insert(
                    "port".into(),
                    json!(port.parse::<u16>().map_err(|_| invalid())?),
                );
            }
            copy_query(
                &mut node,
                &link,
                &[
                    ("multiplexing", "multiplexing"),
                    ("handshake-mode", "handshake-mode"),
                    ("traffic-pattern", "traffic-pattern"),
                ],
            );
            parser.push(node)?;
        }
        return Ok(());
    }
    let kind = match scheme {
        "hy2" | "hysteria2" => "hysteria2",
        "socks" | "socks5" | "socks5h" => "socks5",
        "http" | "https" => "http",
        value => value,
    };
    let mut node = link.base(kind, (kind == "hysteria2").then_some(443))?;
    match kind {
        "hysteria2" => {
            node.insert(
                "password".into(),
                json!(link.user()? + &link.password()?.map_or(String::new(), |v| format!(":{v}"))),
            );
            node.insert(
                "skip-cert-verify".into(),
                json!(boolean(link.get("insecure"))),
            );
            node.insert("udp".into(), json!(true));
            copy_query(
                &mut node,
                &link,
                &[
                    ("obfs", "obfs"),
                    ("obfs-password", "obfs-password"),
                    ("sni", "sni"),
                    ("pinSHA256", "fingerprint"),
                    ("up", "up"),
                    ("down", "down"),
                ],
            );
            alpn(&mut node, link.get("alpn"));
            if let Some(ports) = hopping {
                node.insert("ports".into(), json!(ports));
            }
        }
        "tuic" => {
            node.insert("uuid".into(), json!(link.user()?));
            node.insert(
                "password".into(),
                json!(link.password()?.ok_or_else(invalid)?),
            );
            node.insert("udp".into(), json!(true));
            copy_query(
                &mut node,
                &link,
                &[
                    ("congestion_control", "congestion-controller"),
                    ("sni", "sni"),
                    ("udp_relay_mode", "udp-relay-mode"),
                ],
            );
            alpn(&mut node, link.get("alpn"));
            if link.get("disable_sni") == "1" {
                node.insert("disable-sni".into(), json!(true));
            }
        }
        "trojan" => {
            node.insert("password".into(), json!(link.user()?));
            node.insert("udp".into(), json!(true));
            node.insert(
                "skip-cert-verify".into(),
                json!(boolean(link.get("allowInsecure"))),
            );
            copy_query(&mut node, &link, &[("sni", "sni"), ("pcs", "fingerprint")]);
            alpn(&mut node, link.get("alpn"));
            node.insert(
                "client-fingerprint".into(),
                json!(if link.get("fp").is_empty() {
                    "chrome"
                } else {
                    link.get("fp")
                }),
            );
            transport(&mut node, &link, kind, &mut parser.budget)?;
        }
        "anytls" => {
            node.insert(
                "password".into(),
                json!(link.password()?.unwrap_or(link.user()?)),
            );
            node.insert("udp".into(), json!(true));
            node.insert(
                "skip-cert-verify".into(),
                json!(link.get("insecure") == "1"),
            );
            copy_query(&mut node, &link, &[("sni", "sni"), ("hpkp", "fingerprint")]);
        }
        "socks5" | "http" => {
            if !link.url.username().is_empty() || link.url.password().is_some() {
                let user = link.user()?;
                let raw = link
                    .password()?
                    .map_or_else(|| user.clone(), |password| format!("{user}:{password}"));
                let decoded = decode64(raw.as_bytes(), false);
                let credentials = decoded
                    .as_deref()
                    .map(std::str::from_utf8)
                    .transpose()
                    .map_err(|_| invalid())?
                    .unwrap_or(&raw);
                let (user, password) = credentials.split_once(':').unwrap_or((credentials, ""));
                node.insert("username".into(), json!(user));
                node.insert("password".into(), json!(password));
            }
            if scheme == "https" {
                node.insert("tls".into(), json!(true));
            }
        }
        _ => return Err(invalid()),
    }
    parser.push(node)
}

fn charge(value: &Value, budget: &mut usize, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(invalid());
    }
    *budget = budget.checked_sub(256).ok_or_else(invalid)?;
    match value {
        Value::String(value) => {
            *budget = budget.checked_sub(value.len() * 4).ok_or_else(invalid)?;
        }
        Value::Array(items) => {
            for item in items {
                charge(item, budget, depth + 1)?;
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                *budget = budget
                    .checked_sub(256 + key.len() * 4)
                    .ok_or_else(invalid)?;
                charge(item, budget, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_json(bytes: &[u8], budget: &mut usize) -> Result<Value> {
    use serde::Deserialize;
    let mut syntax = serde_json::Deserializer::from_slice(bytes);
    serde::de::IgnoredAny::deserialize(&mut syntax).map_err(|_| invalid())?;
    syntax.end().map_err(|_| invalid())?;
    let bounded = crate::config::yaml::parse_with_budget(bytes, budget).map_err(|_| invalid())?;
    serde_yaml_ng::from_value(bounded).map_err(|_| invalid())
}

struct Parser<'a> {
    control: &'a DecodeControl<'a>,
    nodes: Vec<serde_yaml_ng::Value>,
    names: HashSet<String>,
    next_name: BTreeMap<String, usize>,
    budget: usize,
}
impl Parser<'_> {
    fn line(&mut self, line: &str, scheme: &str) -> Result<()> {
        // A live reservation covers every temporary allocation in convert(),
        // including one Mieru expanded node at a time. push() charges retained
        // nodes before the next expansion or YAML conversion can begin.
        let scratch = scratch_allowance(line.len())?;
        self.budget = self.budget.checked_sub(scratch).ok_or_else(invalid)?;
        let result = convert(line, scheme, self);
        self.budget += scratch;
        result
    }

    fn push(&mut self, mut node: Map<String, Value>) -> Result<()> {
        self.control.check()?;
        let base = node
            .get("name")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(invalid)?
            .to_owned();
        let mut name = base.clone();
        let mut index = self.next_name.get(&base).copied().unwrap_or(0);
        if index > 0 {
            name = format!("{base}-{index:02}");
        }
        while self.names.contains(&name) {
            self.control.check()?;
            index += 1;
            name = format!("{base}-{index:02}");
        }
        self.next_name.insert(base, index + 1);
        node.insert("name".into(), json!(name));
        let value = Value::Object(node);
        charge(&value, &mut self.budget, 0)?;
        self.names.insert(name);
        self.nodes
            .push(serde_yaml_ng::to_value(value).map_err(|_| invalid())?);
        Ok(())
    }
}

pub(crate) fn parse(
    bytes: &[u8],
    control: &DecodeControl<'_>,
) -> Result<Vec<serde_yaml_ng::Value>> {
    control.check()?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid());
    }
    // Outer Base64 cleaning and decoding coexist temporarily. The caller's
    // original source buffer is outside this conversion allowance.
    if bytes
        .len()
        .checked_mul(2)
        .is_none_or(|n| n > CONVERSION_BUDGET)
    {
        return Err(invalid());
    }
    let decoded = decode64(bytes, false);
    let input = std::str::from_utf8(decoded.as_deref().unwrap_or(bytes)).map_err(|_| invalid())?;
    let mut parser = Parser {
        control,
        nodes: Vec::new(),
        names: HashSet::new(),
        next_name: BTreeMap::new(),
        budget: CONVERSION_BUDGET - decoded.as_ref().map_or(0, Vec::len),
    };
    for line in input.lines() {
        control.check()?;
        let line = line.trim_end_matches([' ', '\r']);
        if line.len() > MAX_URI_LINE_BYTES {
            return Err(invalid());
        }
        let Some((scheme, _)) = line.split_once("://") else {
            continue;
        };
        if scheme.len() > 16 {
            continue;
        }
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(
            scheme.as_str(),
            "hysteria2"
                | "hy2"
                | "tuic"
                | "trojan"
                | "vless"
                | "vmess"
                | "ss"
                | "socks"
                | "socks5"
                | "socks5h"
                | "http"
                | "https"
                | "anytls"
                | "mierus"
        ) {
            continue;
        }
        parser.line(line, &scheme)?;
    }
    control.check()?;
    if parser.nodes.is_empty() {
        return Err(invalid());
    }
    Ok(parser.nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn control() -> DecodeControl<'static> {
        DecodeControl::new(None, Instant::now() + Duration::from_secs(10))
    }

    fn one(input: &str) -> serde_yaml_ng::Value {
        let mut nodes = parse(input.as_bytes(), &control()).unwrap();
        assert_eq!(nodes.len(), 1);
        nodes.remove(0)
    }

    #[test]
    fn subscription_plain_base64_names_and_same_schema() {
        let input =
            "socks5://alice:pass@proxy.invalid:1080#edge\r\nsocks5://proxy.invalid:1081#edge\n";
        for bytes in [
            input.as_bytes().to_vec(),
            STANDARD.encode(input).into_bytes(),
            STANDARD_NO_PAD.encode(input).into_bytes(),
        ] {
            let nodes = parse(&bytes, &control()).unwrap();
            assert_eq!(nodes[0]["name"].as_str(), Some("edge"));
            assert_eq!(nodes[1]["name"].as_str(), Some("edge-01"));
            assert_eq!(nodes[0]["username"].as_str(), Some("alice"));
            assert_eq!(nodes[0]["password"].as_str(), Some("pass"));
            let yaml = serde_yaml_ng::to_string(&serde_json::json!({"proxies":nodes})).unwrap();
            if cfg!(feature = "outbound-socks5") {
                crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
            }
        }
    }

    #[test]
    fn supported_uri_values_are_consumed_by_existing_node_schema() {
        let uuid = "00000000-0000-4000-8000-000000000001";
        let cases = [
            (cfg!(feature="outbound-vless"), format!("vless://{uuid}@proxy.invalid:443?security=tls&type=ws&sni=proxy.invalid&host=cover.invalid&path=%2Fedge&ed=64#edge")),
            (cfg!(feature="outbound-vmess"), format!("vmess://{uuid}@proxy.invalid:443?security=tls&type=grpc&serviceName=edge#edge")),
            (cfg!(feature="outbound-trojan"), "trojan://password@proxy.invalid:443?type=grpc&serviceName=edge#edge".into()),
            (cfg!(feature="outbound-anytls"), "anytls://pa%3Ass@proxy.invalid:443?sni=proxy.invalid#edge".into()),
            (cfg!(feature="outbound-tuic"), format!("tuic://{uuid}:password@proxy.invalid:443?congestion_control=bbr#edge")),
            (cfg!(feature="outbound-hysteria2"), "hy2://password@proxy.invalid:443,444-445?sni=proxy.invalid#edge".into()),
            (cfg!(feature="outbound-http"), "https://alice:password@proxy.invalid:443#edge".into()),
            (cfg!(feature="outbound-http"), "http://proxy.invalid:80#edge".into()),
            (cfg!(feature="outbound-mieru"), "mierus://alice:password@proxy.invalid?port=1234&protocol=TCP&multiplexing=MULTIPLEXING_MIDDLE#edge".into()),
            (cfg!(feature="outbound-shadowsocks"), format!("ss://{}@proxy.invalid:443#edge", URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{}", STANDARD.encode([7u8;16]))))),
        ];
        for (enabled, input) in cases {
            let nodes = parse(input.as_bytes(), &control()).unwrap();
            if input.starts_with("mierus:") {
                assert_eq!(
                    nodes[0]["multiplexing"].as_str(),
                    Some("MULTIPLEXING_MIDDLE")
                );
            }
            let yaml = serde_yaml_ng::to_string(&serde_json::json!({"proxies":nodes})).unwrap();
            if enabled {
                crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
            }
        }
    }

    #[test]
    fn vmess_json_and_vless_xhttp_translate_transports_without_second_schema() {
        let uuid = "00000000-0000-4000-8000-000000000001";
        let vmess = json!({"v":"2","ps":"edge","add":"proxy.invalid","port":"443","id":uuid,"aid":"0","net":"ws","host":"cover.invalid","path":"/edge?ed=32&token=fixture","tls":"tls"});
        let node = one(&format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&vmess).unwrap())
        ));
        assert_eq!(
            node["ws-opts"]["path"].as_str(),
            Some("/edge?token=fixture")
        );
        assert_eq!(node["ws-opts"]["max-early-data"].as_u64(), Some(32));
        if cfg!(feature = "outbound-vmess") {
            crate::config::Config::parse_yaml(
                serde_yaml_ng::to_string(&json!({"proxies":[node]}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        }
        let mut url = Url::parse(&format!("vless://{uuid}@proxy.invalid:443")).unwrap();
        url.query_pairs_mut().append_pair("security","tls").append_pair("type","xhttp").append_pair("path","/edge").append_pair("mode","packet-up").append_pair("extra",&json!({"xmux":{"maxConnections":2,"hKeepAlivePeriod":-1},"scMaxEachPostBytes":8192,"scMinPostsIntervalMs":1}).to_string());
        let node = one(url.as_str());
        assert_eq!(
            node["xhttp-opts"]["reuse-settings"]["max-connections"].as_str(),
            Some("2")
        );
        if cfg!(feature = "outbound-vless") {
            crate::config::Config::parse_yaml(
                serde_yaml_ng::to_string(&json!({"proxies":[node]}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        }
    }

    #[test]
    fn subscription_limits_cancellation_and_errors_are_bounded_and_private() {
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        assert!(
            parse(
                b"socks5://proxy.invalid:1080",
                &DecodeControl::new(Some(&token), Instant::now() + Duration::from_secs(5))
            )
            .is_err()
        );
        assert!(parse(&vec![b'A'; MAX_CONFIG_BYTES + 1], &control()).is_err());
        assert!(
            parse(
                b"socks5://secret-user:secret-pass@proxy.invalid",
                &control()
            )
            .unwrap_err()
            .to_string()
            .contains("invalid or unsupported")
        );
        let error = parse(b"ss://legacy:secret@proxy.invalid:443", &control())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
        let mut budget = 64;
        assert!(charge(&json!({"field":"value"}), &mut budget, 0).is_err());
        assert!(parse(b"plain unrelated content", &control()).is_err());
    }

    #[test]
    fn scratch_is_reserved_before_conversion_and_multiport_expansion_stays_bounded() {
        let control = control();
        let line = "socks5://proxy.invalid:1080";
        let remaining = scratch_allowance(line.len()).unwrap() - 1;
        let mut parser = Parser {
            control: &control,
            nodes: Vec::new(),
            names: HashSet::new(),
            next_name: BTreeMap::new(),
            budget: remaining,
        };
        assert!(parser.line(line, "socks5").is_err());
        assert_eq!(parser.budget, remaining);
        assert!(parser.nodes.is_empty());
        assert!(parser.names.is_empty());
        assert!(parser.next_name.is_empty());

        let long = format!(
            "socks5://proxy.invalid:1080#{}",
            "x".repeat(MAX_URI_LINE_BYTES)
        );
        assert!(parse(long.as_bytes(), &control).is_err());
        let mut multiport = format!("mierus://{}:password@proxy.invalid?", "x".repeat(8192));
        for port in 1..=1000 {
            multiport.push_str(&format!("port={port}&protocol=TCP&"));
        }
        assert!(multiport.len() < MAX_URI_LINE_BYTES);
        assert!(parse(multiport.as_bytes(), &control).is_err());
    }
}
