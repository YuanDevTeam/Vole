//! On-demand DNS diagnostics over the existing raw upstream resolver.
use std::{fmt, io};

use domain::{
    base::{Message, ParsedName, Question, Record, RecordData, name::ToName},
    rdata::AllRecordData,
};
use serde::{
    Serialize, Serializer,
    ser::{Error as _, SerializeMap, SerializeSeq},
};
use tokio_util::sync::CancellationToken;

use super::{ControllerIo, write_error, write_response};

const MAX_JSON_BYTES: usize = 256 * 1024;

pub(super) async fn query<S: ControllerIo>(
    stream: &mut S,
    target: &str,
    resources: Option<&dyn crate::resource::control::RuntimeResources>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let Some(snapshot) = resources
        .and_then(|resources| resources.dns())
        .filter(|snapshot| snapshot.dns.is_enabled())
    else {
        return write_error(stream, 500, "DNS is disabled", &[]).await;
    };
    let Ok(query) = question(target) else {
        return write_error(stream, 400, "Bad request", &[]).await;
    };
    let (result, path) = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = crate::dns::trace::capture(snapshot.dns.query_upstream(&query)) => result,
    };
    let Ok(wire) = result else {
        return write_error(stream, 500, "DNS query failed", &[]).await;
    };
    let Ok(body) = response(&wire, &path) else {
        return write_error(stream, 500, "DNS response invalid", &[]).await;
    };
    // Keep the selected resource generation alive until output is complete.
    write_response(stream, 200, &[("Content-Type", "application/json")], &body).await
}

fn question(target: &str) -> Result<Vec<u8>, ()> {
    if target.contains('#') {
        return Err(());
    }
    let mut name = None;
    let mut kind = None;
    for (key, value) in
        url::form_urlencoded::parse(target.split_once('?').map_or("", |(_, q)| q).as_bytes())
    {
        match key.as_ref() {
            "name" if name.is_none() => name = Some(value),
            "type" if kind.is_none() => kind = Some(value),
            _ => return Err(()),
        }
    }
    let kind = query_type(kind.as_deref().unwrap_or_default()).ok_or(())?;
    crate::dns::build_wire_query(1, name.as_deref().unwrap_or_default(), kind).map_err(|_| ())
}

/// Mihomo's Controller uses the case-sensitive miekg/dns v1.1.63 StringToType table.
/// Keep wire qtypes separate from the address-only business resolver model.
fn query_type(name: &str) -> Option<u16> {
    Some(match name {
        "" | "A" => 1,
        "AAAA" => 28,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "NXNAME" => 128,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "AMTRELAY" => 260,
        "TA" => 32768,
        "DLV" => 32769,
        "None" => 0,
        "Reserved" => 65535,
        _ => return None,
    })
}

fn response(wire: &[u8], path: &[&'static str]) -> Result<Vec<u8>, ()> {
    if !(12..=crate::dns::MAX_MESSAGE_SIZE).contains(&wire.len())
        || wire[2] & 0xfa != 0x80 // QR, opcode 0, and no truncated response.
        || wire[3] & 0x40 != 0
        || wire[4..6] != [0, 1]
    {
        return Err(());
    }
    let message = Message::from_octets(wire).map_err(|_| ())?;
    let question = message.sole_question().map_err(|_| ())?;
    if question.qclass().to_int() != 1 {
        return Err(());
    }
    let mut body = BoundedJson(Vec::new());
    serde_json::to_writer(&mut body, &Response { wire, path }).map_err(|_| ())?;
    Ok(body.0)
}

struct Response<'a> {
    wire: &'a [u8],
    path: &'a [&'static str],
}
impl Serialize for Response<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let message = Message::from_octets(self.wire).map_err(S::Error::custom)?;
        let question = message.sole_question().map_err(S::Error::custom)?;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("Status", &message.opt_rcode().to_int())?;
        map.serialize_entry("Question", &[QuestionView(&question)])?;
        map.serialize_entry(
            "Answer",
            &Section {
                wire: self.wire,
                kind: 0,
            },
        )?;
        for (key, kind, count) in [
            ("Authority", 1, message.header_counts().nscount()),
            ("Additional", 2, message.header_counts().arcount()),
        ] {
            if count != 0 {
                map.serialize_entry(
                    key,
                    &Section {
                        wire: self.wire,
                        kind,
                    },
                )?;
            }
        }
        // Even empty sections must be scanned to reject trailing wire bytes.
        if message.header_counts().arcount() == 0 {
            let mut additional = message.additional().map_err(S::Error::custom)?;
            for record in additional.by_ref() {
                record.map_err(S::Error::custom)?;
            }
            if additional.pos() != self.wire.len() {
                return Err(S::Error::custom("trailing DNS data"));
            }
        }
        map.serialize_entry("TC", &(self.wire[2] & 2 != 0))?;
        map.serialize_entry("RD", &(self.wire[2] & 1 != 0))?;
        map.serialize_entry("RA", &(self.wire[3] & 0x80 != 0))?;
        map.serialize_entry("AD", &(self.wire[3] & 0x20 != 0))?;
        map.serialize_entry("CD", &(self.wire[3] & 0x10 != 0))?;
        map.serialize_entry("QueryPath", self.path)?;
        map.end()
    }
}

struct QuestionView<'a, N>(&'a Question<N>);
impl<N: ToName> Serialize for QuestionView<'_, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("Name", &DisplayValue(self.0.qname().fmt_with_dot()))?;
        map.serialize_entry("Qtype", &self.0.qtype().to_int())?;
        map.serialize_entry("Qclass", &self.0.qclass().to_int())?;
        map.end()
    }
}

struct Section<'a> {
    wire: &'a [u8],
    kind: u8,
}
impl Serialize for Section<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let message = Message::from_octets(self.wire).map_err(S::Error::custom)?;
        let mut section = match self.kind {
            0 => message.answer(),
            1 => message.authority(),
            _ => message.additional(),
        }
        .map_err(S::Error::custom)?;
        let mut records = serializer.serialize_seq(None)?;
        for record in section.by_ref() {
            let record = record
                .map_err(S::Error::custom)?
                .into_any_record::<AllRecordData<_, ParsedName<_>>>()
                .map_err(S::Error::custom)?;
            records.serialize_element(&RecordView(&record))?;
        }
        if self.kind == 2 && section.pos() != self.wire.len() {
            return Err(S::Error::custom("trailing DNS data"));
        }
        records.end()
    }
}

struct RecordView<'a, N, D>(&'a Record<N, D>);
impl<N: ToName, D: RecordData + fmt::Display> Serialize for RecordView<'_, N, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("name", &DisplayValue(self.0.owner().fmt_with_dot()))?;
        map.serialize_entry("type", &self.0.rtype().to_int())?;
        map.serialize_entry("TTL", &self.0.ttl().as_secs())?;
        map.serialize_entry("data", &DisplayValue(self.0.data()))?;
        map.end()
    }
}

struct DisplayValue<T>(T);
impl<T: fmt::Display> Serialize for DisplayValue<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // serde_json streams Display through its escaping writer, without an
        // intermediate unbounded name/RDATA String or generic record tree.
        serializer.collect_str(&self.0)
    }
}

struct BoundedJson(Vec<u8>);
impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let needed = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_JSON_BYTES)
            .ok_or_else(|| io::Error::other("DNS diagnostic output exceeded budget"))?;
        if needed > self.0.capacity() {
            let capacity = self
                .0
                .capacity()
                .saturating_mul(2)
                .max(512)
                .max(needed)
                .min(MAX_JSON_BYTES);
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn packet(kind: u16) -> Vec<u8> {
        let mut wire = crate::dns::build_wire_query(1, "example.com", kind).unwrap();
        wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        wire
    }
    fn rr(wire: &mut Vec<u8>, kind: u16, ttl: u32, data: &[u8]) {
        wire.extend_from_slice(&[0xc0, 0x0c]);
        wire.extend_from_slice(&kind.to_be_bytes());
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
        wire.extend_from_slice(data);
    }
    fn displayed(wire: &[u8]) -> Value {
        serde_json::from_slice(&response(wire, &["upstream"]).unwrap()).unwrap()
    }

    #[test]
    fn query_types_keep_mihomo_names_case_and_strict_parameters() {
        for (name, kind) in [
            ("", 1),
            ("AAAA", 28),
            ("TXT", 16),
            ("HTTPS", 65),
            ("NSAP-PTR", 23),
            ("NXNAME", 128),
            ("ANY", 255),
            ("None", 0),
            ("Reserved", 65535),
        ] {
            let wire = question(&format!("/dns/query?name=Example.com&type={name}")).unwrap();
            assert_eq!(
                crate::dns::classify_query(&wire)
                    .unwrap()
                    .question
                    .query_type,
                kind
            );
        }
        assert!(question("/dns/query?name=example.com").is_ok());
        for target in [
            "/dns/query?name=example.com&type=txt",
            "/dns/query?name=example.com&type=TYPE65400",
            "/dns/query?name=example.com&type=WKS",
            "/dns/query?name=example.com&type=RESINFO",
            "/dns/query?name=example.com&type=1",
            "/dns/query?name=example.com&type=A&type=AAAA",
            "/dns/query?name=example.com&extra=x",
            "/dns/query?name=example.com#secret",
        ] {
            assert!(question(target).is_err(), "{target}");
        }
    }

    #[test]
    fn raw_records_preserve_sections_ttl_and_address_response_shape() {
        let mut wire = packet(16);
        wire[6..12].copy_from_slice(&[0, 1, 0, 1, 0, 1]);
        rr(&mut wire, 16, 17, b"\x03txt");
        let mut soa = b"\x02ns\x07example\x03com\0\x0ahostmaster\x07example\x03com\0".to_vec();
        for value in [42_u32, 60, 30, 120, 15] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        rr(&mut wire, 6, 123, &soa);
        rr(&mut wire, 1, 9, &[192, 0, 2, 7]);
        let value = displayed(&wire);
        assert_eq!(value["Status"], 0);
        assert_eq!(
            value["Question"],
            json!([{"Name":"example.com.", "Qtype":16, "Qclass":1}])
        );
        assert_eq!(
            value["Answer"],
            json!([{"name":"example.com.", "type":16, "TTL":17, "data":"\"txt\""}])
        );
        assert_eq!(value["Authority"][0]["type"], 6);
        assert_eq!(value["Authority"][0]["TTL"], 123);
        assert_eq!(
            value["Authority"][0]["data"],
            "ns.example.com. hostmaster.example.com. 42 60 30 120 15"
        );
        assert_eq!(
            value["Additional"],
            json!([{"name":"example.com.", "type":1, "TTL":9, "data":"192.0.2.7"}])
        );
        assert_eq!(value["QueryPath"], json!(["upstream"]));
        assert_eq!(value["RD"], true);
        assert_eq!(value["RA"], true);

        let mut address = packet(1);
        address[6..8].copy_from_slice(&1_u16.to_be_bytes());
        rr(&mut address, 1, 27, &[192, 0, 2, 8]);
        let value = displayed(&address);
        assert_eq!(
            value["Answer"],
            json!([{"name":"example.com.", "type":1, "TTL":27, "data":"192.0.2.8"}])
        );
        assert!(value.get("Authority").is_none());
        assert!(value.get("Additional").is_none());
    }

    #[test]
    fn unknown_data_and_malformed_wire_keep_their_actual_status() {
        let mut unknown = packet(255);
        unknown[6..8].copy_from_slice(&1_u16.to_be_bytes());
        rr(&mut unknown, 65400, 2, &[1, 2, 3]);
        assert_eq!(displayed(&unknown)["Answer"][0]["data"], "\\# 3 01 02 03");
        for invalid in [
            {
                let mut wire = unknown.clone();
                wire.push(0);
                wire
            },
            {
                let mut wire = unknown.clone();
                wire[2] |= 2;
                wire
            },
            {
                let mut wire = unknown.clone();
                wire.pop();
                wire
            },
            {
                let mut wire = packet(1);
                wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
                rr(&mut wire, 1, 2, &[1, 2, 3]);
                wire
            },
        ] {
            assert!(response(&invalid, &[]).is_err());
        }
    }

    #[test]
    fn escaping_stops_before_diagnostic_output_growth() {
        struct Escaped;
        impl fmt::Display for Escaped {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..MAX_JSON_BYTES {
                    f.write_str("\"\\")?;
                }
                Ok(())
            }
        }
        let mut writer = BoundedJson(Vec::new());
        assert!(serde_json::to_writer(&mut writer, &DisplayValue(Escaped)).is_err());
        assert!(writer.0.len() <= MAX_JSON_BYTES);
        assert!(writer.0.capacity() <= MAX_JSON_BYTES);
    }
}
