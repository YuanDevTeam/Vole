//! Per-upstream DNS query wrappers, independent of the physical source.

use std::{borrow::Cow, net::IpAddr};

use domain::{
    base::{Message, MessageBuilder, ParsedName, StaticCompressor},
    rdata::AllRecordData,
};

use crate::config::DnsNameserverOptions;

use super::{
    DnsError, MAX_MESSAGE_SIZE, MAX_RESPONSE_RECORDS, Result, classify_query, decode_name,
    parse_wire_question_header, read_u16, scan_record,
};

pub(super) fn question_disabled(options: &DnsNameserverOptions, qtype: u16) -> bool {
    options.disabled_types.binary_search(&qtype).is_ok()
}

/// Preserves an existing ECS unless override was explicitly requested. Only
/// the first ECS is replaced, retaining its scope and all other EDNS options.
pub(super) fn with_ecs<'a>(
    query: &'a [u8],
    options: &DnsNameserverOptions,
) -> Result<Cow<'a, [u8]>> {
    let Some(ecs) = options.ecs else {
        return Ok(Cow::Borrowed(query));
    };
    classify_query(query)?;
    let header = parse_wire_question_header(query)?;
    let mut data_start = query.len();
    let mut data_end = query.len();
    let mut length_offset = None;
    if header.additional_count != 0 {
        let mut cursor = header.records_offset;
        let record = scan_record(query, &mut cursor)?;
        data_start = usize::from(record.data_start);
        data_end = usize::from(record.data_end);
        length_offset = Some(data_start - 2);
    }
    let mut replace = None;
    let mut scope = 0;
    let mut cursor = data_start;
    while cursor < data_end {
        let code = read_u16(query, cursor)?;
        let end = cursor + 4 + usize::from(read_u16(query, cursor + 2)?);
        if code == 8 {
            if !options.ecs_override {
                return Ok(Cow::Borrowed(query));
            }
            if end < cursor + 8 {
                return Err(DnsError::InvalidRecord);
            }
            scope = query[cursor + 7];
            replace = Some(cursor..end);
            break;
        }
        cursor = end;
    }
    let (family, bytes): (u16, Vec<u8>) = match ecs.address {
        IpAddr::V4(address) => (1, address.octets().to_vec()),
        IpAddr::V6(address) => (2, address.octets().to_vec()),
    };
    if usize::from(ecs.prefix_len) > bytes.len() * 8 {
        return Err(DnsError::InvalidRecord);
    }
    let address_len = usize::from(ecs.prefix_len).div_ceil(8);
    let mut option = Vec::with_capacity(8 + address_len);
    option.extend_from_slice(&8_u16.to_be_bytes());
    option.extend_from_slice(&(4 + address_len as u16).to_be_bytes());
    option.extend_from_slice(&family.to_be_bytes());
    option.extend_from_slice(&[ecs.prefix_len, scope]);
    option.extend_from_slice(&bytes[..address_len]);
    if ecs.prefix_len % 8 != 0 {
        *option
            .last_mut()
            .expect("a partial prefix has an address byte") &= 0xff << (8 - ecs.prefix_len % 8);
    }
    let replaced_len = replace.as_ref().map_or(0, |range| range.len());
    let extra_record = usize::from(length_offset.is_none()) * 11;
    let output_len = query.len() - replaced_len + option.len() + extra_record;
    if output_len > MAX_MESSAGE_SIZE {
        return Err(DnsError::MessageTooLarge);
    }
    let mut output = Vec::with_capacity(output_len);
    if let Some(range) = replace {
        output.extend_from_slice(&query[..range.start]);
        output.extend_from_slice(&option);
        output.extend_from_slice(&query[range.end..]);
    } else {
        output.extend_from_slice(query);
        if length_offset.is_none() {
            // Mihomo's new OPT has a zero advertised UDP size and no flags.
            output.extend_from_slice(&[0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0]);
            output[10..12].copy_from_slice(&1_u16.to_be_bytes());
            length_offset = Some(output.len() - 2);
        }
        output.extend_from_slice(&option);
    }
    let data_len = data_end - data_start - replaced_len + option.len();
    let offset = length_offset.expect("ECS always belongs to an OPT record");
    output[offset..offset + 2].copy_from_slice(&(data_len as u16).to_be_bytes());
    Ok(Cow::Owned(output))
}

/// Re-composes every surviving RR so names compressed against a removed RR
/// cannot retain stale offsets. The official codec understands all RFC 1035
/// compressible RDATA; RFC 3597 unknown RDATA remains byte-for-byte opaque.
pub(super) fn filter_response(wire: &[u8], disabled: &[u16]) -> Result<Vec<u8>> {
    preflight_names(wire)?;
    let message = Message::from_octets(wire).map_err(|_| DnsError::InvalidRecord)?;
    let mut builder = MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
        .map_err(|_| DnsError::MessageTooLarge)?;
    builder.set_push_limit(MAX_MESSAGE_SIZE);
    *builder.header_mut() = message.header();
    let mut builder = builder.question();
    for question in message.question() {
        builder
            .push(question.map_err(|_| DnsError::InvalidRecord)?)
            .map_err(|_| DnsError::MessageTooLarge)?;
    }
    let mut builder = builder.answer();
    for record in message
        .answer()
        .map_err(|_| DnsError::InvalidRecord)?
        .into_records::<AllRecordData<_, ParsedName<_>>>()
    {
        let record = record.map_err(|_| DnsError::InvalidRecord)?;
        if disabled.binary_search(&record.rtype().to_int()).is_err() {
            builder
                .push(record)
                .map_err(|_| DnsError::MessageTooLarge)?;
        }
    }
    let mut builder = builder.authority();
    for record in message
        .authority()
        .map_err(|_| DnsError::InvalidRecord)?
        .into_records::<AllRecordData<_, ParsedName<_>>>()
    {
        let record = record.map_err(|_| DnsError::InvalidRecord)?;
        if disabled.binary_search(&record.rtype().to_int()).is_err() {
            builder
                .push(record)
                .map_err(|_| DnsError::MessageTooLarge)?;
        }
    }
    let mut builder = builder.additional();
    for record in message
        .additional()
        .map_err(|_| DnsError::InvalidRecord)?
        .into_records::<AllRecordData<_, ParsedName<_>>>()
    {
        let record = record.map_err(|_| DnsError::InvalidRecord)?;
        if disabled.binary_search(&record.rtype().to_int()).is_err() {
            builder
                .push(record)
                .map_err(|_| DnsError::MessageTooLarge)?;
        }
    }
    Ok(builder.finish().into_target())
}

/// Retains Core's smaller name/pointer budget before the borrowed codec
/// parses name-bearing RDATA. Binary RDATA is never searched for pointers.
fn preflight_names(wire: &[u8]) -> Result<()> {
    let header = parse_wire_question_header(wire)?;
    let count = usize::from(header.answer_count)
        + usize::from(header.authority_count)
        + usize::from(header.additional_count);
    if count > MAX_RESPONSE_RECORDS {
        return Err(DnsError::TooManyRecords);
    }
    let mut cursor = header.records_offset;
    for _ in 0..count {
        let record = scan_record(wire, &mut cursor)?;
        let mut name_cursor = usize::from(record.data_start);
        let end = usize::from(record.data_end);
        let (prefix, names, exact) = match record.record_type {
            2..=5 | 7..=9 | 12 | 39 => (0, 1, true),
            6 => (0, 2, false),
            14 | 17 => (0, 2, true),
            15 => (2, 1, true),
            33 => (6, 1, true),
            46 => (18, 1, false),
            47 | 250 => (0, 1, false),
            64 | 65 => (2, 1, false),
            45 if wire.get(name_cursor + 1) == Some(&3) => (3, 1, false),
            35 => {
                name_cursor += 4;
                for _ in 0..3 {
                    let length =
                        usize::from(*wire.get(name_cursor).ok_or(DnsError::InvalidRecord)?);
                    name_cursor += length + 1;
                    if name_cursor > end {
                        return Err(DnsError::InvalidRecord);
                    }
                }
                (0, 1, true)
            }
            _ => continue,
        };
        name_cursor += prefix;
        for _ in 0..names {
            if name_cursor >= end {
                return Err(DnsError::InvalidRecord);
            }
            let (_, consumed) = decode_name(wire, name_cursor)?;
            name_cursor += consumed;
            if name_cursor > end {
                return Err(DnsError::InvalidRecord);
            }
        }
        if exact && name_cursor != end || record.record_type == 6 && name_cursor + 20 != end {
            return Err(DnsError::InvalidRecord);
        }
    }
    if cursor != wire.len() {
        return Err(DnsError::TrailingData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::DnsEcs,
        dns::{QueryType, build_query, validate_opaque_response},
    };

    fn options(address: &str, prefix_len: u8) -> DnsNameserverOptions {
        DnsNameserverOptions {
            ecs: Some(DnsEcs {
                address: address.parse().unwrap(),
                prefix_len,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn upstream_ecs_masks_prefix_and_preserves_other_options_and_scope() {
        let query = build_query(7, "ecs.example", QueryType::A).unwrap();
        let mut ipv4 = with_ecs(&query, &options("192.0.2.255", 25))
            .unwrap()
            .into_owned();
        assert_eq!(
            &ipv4[ipv4.len() - 12..],
            &[0, 8, 0, 8, 0, 1, 25, 0, 192, 0, 2, 128]
        );
        let header = parse_wire_question_header(&ipv4).unwrap();
        let mut cursor = header.records_offset;
        let record = scan_record(&ipv4, &mut cursor).unwrap();
        assert_eq!(record.record_class, 0);
        assert_eq!(record.ttl, 0);
        let start = usize::from(record.data_start);
        ipv4[start + 7] = 17;
        // Append a non-ECS EDNS option, keeping its exact bytes.
        ipv4.extend_from_slice(&[0, 12, 0, 2, 0xc0, 0xff]);
        ipv4[start - 2..start].copy_from_slice(&18_u16.to_be_bytes());
        let unchanged = with_ecs(&ipv4, &options("2001:db8::ffff", 57)).unwrap();
        assert!(matches!(unchanged, Cow::Borrowed(_)));
        let mut replacement = options("2001:db8::ffff", 57);
        replacement.ecs_override = true;
        let output = with_ecs(&ipv4, &replacement).unwrap();
        classify_query(&output).unwrap();
        assert_eq!(&output[start..start + 8], &[0, 8, 0, 12, 0, 2, 57, 17]);
        assert_eq!(
            &output[start + 8..start + 16],
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0]
        );
        assert_eq!(&output[output.len() - 6..], &[0, 12, 0, 2, 0xc0, 0xff]);
    }

    fn rr(wire: &mut Vec<u8>, owner: &[u8], kind: u16, data: &[u8]) {
        wire.extend_from_slice(owner);
        wire.extend_from_slice(&kind.to_be_bytes());
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&60_u32.to_be_bytes());
        wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
        wire.extend_from_slice(data);
    }

    #[test]
    fn upstream_type_filter_reencodes_removed_compression_targets_in_all_sections() {
        let mut query = build_query(23, "mail.example", QueryType::A).unwrap();
        let offset = query.len() - 4;
        query[offset..offset + 2].copy_from_slice(&15_u16.to_be_bytes());
        let classified = classify_query(&query).unwrap();
        let mut wire = query;
        wire[2] |= 0x80;
        wire[6..8].copy_from_slice(&2_u16.to_be_bytes());
        wire[8..10].copy_from_slice(&2_u16.to_be_bytes());
        wire[10..12].copy_from_slice(&2_u16.to_be_bytes());
        let target = wire.len() as u16 | 0xc000;
        rr(&mut wire, b"\x05alias\x07example\0", 16, b"\x03txt");
        let mut mx = vec![0, 10];
        mx.extend_from_slice(&target.to_be_bytes());
        rr(&mut wire, &[0xc0, 12], 15, &mx);
        let mut soa = Vec::new();
        soa.extend_from_slice(&target.to_be_bytes());
        soa.extend_from_slice(&target.to_be_bytes());
        soa.extend_from_slice(&[0; 20]);
        rr(&mut wire, &[0xc0, 12], 6, &soa);
        rr(&mut wire, &[0xc0, 12], 16, b"\x03txt");
        rr(&mut wire, &[0xc0, 12], 65280, &[0xc0, 0xff, 0, 42]);
        rr(&mut wire, &[0xc0, 12], 16, b"\x03txt");
        let filtered = filter_response(&wire, &[16]).unwrap();
        let header = parse_wire_question_header(&filtered).unwrap();
        assert_eq!(
            (
                header.answer_count,
                header.authority_count,
                header.additional_count
            ),
            (1, 1, 1)
        );
        let mut cursor = header.records_offset;
        let mx = scan_record(&filtered, &mut cursor).unwrap();
        assert_eq!(
            decode_name(&filtered, usize::from(mx.data_start) + 2)
                .unwrap()
                .0,
            "alias.example"
        );
        let soa = scan_record(&filtered, &mut cursor).unwrap();
        assert_eq!(
            decode_name(&filtered, usize::from(soa.data_start))
                .unwrap()
                .0,
            "alias.example"
        );
        let unknown = scan_record(&filtered, &mut cursor).unwrap();
        assert_eq!(
            &filtered[usize::from(unknown.data_start)..usize::from(unknown.data_end)],
            &[0xc0, 0xff, 0, 42]
        );
        assert_eq!(
            validate_opaque_response(&classified, &filtered)
                .unwrap()
                .ttl_offsets
                .len(),
            3
        );
    }

    #[test]
    fn upstream_type_filter_retains_core_pointer_and_output_budgets() {
        let query = build_query(3, "budget.example", QueryType::A).unwrap();
        let mut wire = query;
        wire[2] |= 0x80;
        wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
        let mut chain = 12_u16;
        // Null binary RDATA supplies a legal place for a deliberately excessive
        // chain used by the later CNAME, without treating all binary bytes as names.
        let mut data = vec![];
        let data_start = wire.len() + 12;
        for index in 0..17 {
            data.extend_from_slice(&(chain | 0xc000).to_be_bytes());
            chain = (data_start + index * 2) as u16;
        }
        rr(&mut wire, &[0xc0, 12], 10, &data);
        wire[6..8].copy_from_slice(&2_u16.to_be_bytes());
        rr(&mut wire, &[0xc0, 12], 5, &(chain | 0xc000).to_be_bytes());
        assert_eq!(
            filter_response(&wire, &[16]),
            Err(DnsError::TooManyCompressionJumps)
        );
        let name = ["a".repeat(63), "b".repeat(63), "c".repeat(63)].join(".");
        let mut wire = build_query(4, &name, QueryType::A).unwrap();
        wire[2] |= 0x80;
        wire[6..8].copy_from_slice(&64_u16.to_be_bytes());
        for _ in 0..64 {
            // A legacy compressed DNAME is expanded by the codec as required
            // for non-RFC1035 RDATA; expansion must still obey our output cap.
            rr(&mut wire, &[0xc0, 12], 39, &[0xc0, 12]);
        }
        assert!(wire.len() < MAX_MESSAGE_SIZE);
        assert_eq!(
            filter_response(&wire, &[16]),
            Err(DnsError::MessageTooLarge)
        );
    }
}
