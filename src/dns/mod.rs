//! Bounded DNS wire primitives and caches used by the runtime DNS service.
//!
//! This module deliberately contains no network transport. Callers own query
//! scheduling and cancellation. Every allocation retained by the cache and
//! redir-host table is bounded by the configured count and wire/record limits,
//! while concurrent query
//! activity is observed rather than rejected by a fixed local admission cap.

mod cache;
pub(crate) mod fake_ip;
mod fallback;
pub(crate) mod hosts;
mod https;
pub(crate) mod policy;
pub(crate) mod trace;

pub mod resolution;
pub mod runtime;

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use sha2::{Digest as _, Sha256};

pub const MAX_MESSAGE_SIZE: usize = 4_096;
/// Maximum number of resource records scanned across all response sections.
pub const MAX_RESPONSE_RECORDS: usize = 64;
/// Maximum number of unique addresses retained in the typed cache and hints.
pub const MAX_ANSWERS: usize = 16;
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_COMPRESSION_JUMPS: usize = 16;
/// Default result count per DNS role; configuration may choose another count.
pub const MAX_CACHE_ENTRIES: usize = 4_096;
pub const MAX_REDIR_HOST_ENTRIES: usize = 256;
pub const MAX_OPAQUE_RECORDS: usize = 64;
pub const MAX_OPAQUE_CACHE_ENTRIES: usize = 64;
pub const MAX_OPAQUE_CACHE_BYTES: usize = 256 * 1024;
pub const MAX_OPAQUE_CACHE_ENTRY_BYTES: usize = MAX_MESSAGE_SIZE;

pub const MIN_TTL_SECS: u32 = 30;
pub const MAX_TTL_SECS: u32 = 3_600;
pub const NEGATIVE_TTL_SECS: u32 = 30;

const DNS_HEADER_LEN: usize = 12;
const CLASS_IN: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_OPT: u16 = 41;
const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

pub type Result<T> = std::result::Result<T, DnsError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    MessageTooLarge,
    Truncated,
    TruncatedResponse,
    NotAQuery,
    NotAResponse,
    UnsupportedOpcode,
    ReservedFlag,
    InvalidQuestionCount,
    QueryContainsAnswers,
    QueryContainsAuthorityRecords,
    TooManyAnswers,
    TooManyRecords,
    UnsupportedQuestionType,
    UnsupportedQuestionClass,
    InvalidName,
    NameTooLong,
    CompressionPointerLoop,
    TooManyCompressionJumps,
    InvalidRecord,
    InvalidCnameChain,
    TrailingData,
    EmptyCacheValue,
    TooManyCacheAddresses,
    AddressFamilyMismatch,
    InvalidRcode,
    ResponseMismatch,
    ExpectedOpaqueQuestion,
    CacheAllocation,
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MessageTooLarge => "DNS message exceeds 4096 bytes",
            Self::Truncated => "truncated DNS message",
            Self::TruncatedResponse => "DNS response has the TC flag set",
            Self::NotAQuery => "DNS message is not a query",
            Self::NotAResponse => "DNS message is not a response",
            Self::UnsupportedOpcode => "unsupported DNS opcode",
            Self::ReservedFlag => "reserved DNS flag is set",
            Self::InvalidQuestionCount => "DNS message must contain exactly one question",
            Self::QueryContainsAnswers => "DNS query contains answer records",
            Self::QueryContainsAuthorityRecords => "DNS query contains authority records",
            Self::TooManyAnswers => "DNS response contains more than 64 resource records",
            Self::TooManyRecords => "DNS message contains more than 64 resource records",
            Self::UnsupportedQuestionType => "DNS question type is not A or AAAA",
            Self::UnsupportedQuestionClass => "DNS question class is not IN",
            Self::InvalidName => "invalid DNS name",
            Self::NameTooLong => "DNS name exceeds 253 bytes",
            Self::CompressionPointerLoop => "DNS compression pointer loop",
            Self::TooManyCompressionJumps => "DNS name exceeds 16 compression jumps",
            Self::InvalidRecord => "invalid DNS resource record",
            Self::InvalidCnameChain => "invalid DNS CNAME chain",
            Self::TrailingData => "DNS message contains trailing data",
            Self::EmptyCacheValue => "positive DNS cache value has no addresses",
            Self::TooManyCacheAddresses => "DNS cache value contains more than 16 addresses",
            Self::AddressFamilyMismatch => "DNS cache address does not match the question type",
            Self::InvalidRcode => "DNS response code exceeds four bits",
            Self::ResponseMismatch => "DNS response ID or question does not match the query",
            Self::ExpectedOpaqueQuestion => "DNS question type is A or AAAA, not opaque",
            Self::CacheAllocation => "DNS cache allocation failed",
        })
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueryType {
    A = 1,
    Aaaa = 28,
}

impl QueryType {
    fn from_wire(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::A),
            28 => Ok(Self::Aaaa),
            _ => Err(DnsError::UnsupportedQuestionType),
        }
    }
}

/// Classification used before choosing the typed A/AAAA path or the bounded
/// opaque relay path. The original 16-bit qtype always remains available on
/// [`WireQuestion::query_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryKind {
    Address(QueryType),
    Opaque,
}

/// Canonical single-question cache and response-validation key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireQuestion {
    pub name: String,
    pub query_type: u16,
    pub query_class: u16,
}

/// A structurally validated single-question IN query. This classifier accepts
/// every 16-bit qtype; callers keep using [`parse_query`] for typed A/AAAA
/// response processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedDnsQuery {
    pub id: u16,
    pub recursion_desired: bool,
    pub question: WireQuestion,
    pub kind: DnsQueryKind,
    question_wire: Box<[u8]>,
    semantics_digest: [u8; 32],
}

impl ClassifiedDnsQuery {
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        matches!(self.kind, DnsQueryKind::Opaque)
    }

    /// Canonical uncompressed question bytes, excluding the DNS header.
    #[must_use]
    pub fn question_wire(&self) -> &[u8] {
        &self.question_wire
    }
}

/// Why a validated opaque response may or may not enter the wire cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueCachePolicy {
    NotCacheable,
    Positive { lifetime_secs: u32 },
    Negative { lifetime_secs: u32 },
}

impl OpaqueCachePolicy {
    const fn lifetime_secs(self) -> Option<u32> {
        match self {
            Self::NotCacheable => None,
            Self::Positive { lifetime_secs } | Self::Negative { lifetime_secs } => {
                Some(lifetime_secs)
            }
        }
    }
}

/// Owned, bounded opaque response produced by [`validate_opaque_response`].
/// The private TTL-offset list is the only mutation metadata retained by the
/// cache; its length is bounded by [`MAX_OPAQUE_RECORDS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOpaqueResponse {
    wire: Box<[u8]>,
    question: WireQuestion,
    semantics_digest: [u8; 32],
    ttl_offsets: Box<[u16]>,
    rcode: u16,
    cache_policy: OpaqueCachePolicy,
}

impl ValidatedOpaqueResponse {
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    #[must_use]
    pub fn into_wire(self) -> Vec<u8> {
        self.wire.into_vec()
    }

    #[must_use]
    pub const fn rcode(&self) -> u16 {
        self.rcode
    }

    #[must_use]
    pub const fn cache_policy(&self) -> OpaqueCachePolicy {
        self.cache_policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: QueryType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub authoritative: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub question: DnsQuestion,
    /// Supported IN-class records from the answer section. Unknown answer
    /// types are validated and skipped without being retained.
    pub answers: Vec<DnsRecord>,
    /// The answer count from the DNS header, including skipped record types.
    pub answer_count: u16,
}

struct ParsedQuestionHeader {
    id: u16,
    flags: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    question: DnsQuestion,
    records_offset: usize,
}

struct WireQuestionHeader {
    id: u16,
    flags: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    question: WireQuestion,
    records_offset: usize,
}

struct ScannedRecord {
    owner: String,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    ttl_offset: u16,
    data_start: u16,
    data_end: u16,
}

/// Builds a recursive A or AAAA query containing exactly one question.
pub fn build_query(id: u16, name: &str, query_type: QueryType) -> Result<Vec<u8>> {
    let name = canonicalize_name(name)?;
    let mut message = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD
    message.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    message.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    message.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    encode_name(&name, &mut message);
    message.extend_from_slice(&(query_type as u16).to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    debug_assert!(message.len() <= MAX_MESSAGE_SIZE);
    Ok(message)
}

/// Classifies a bounded single-question IN query without narrowing its qtype.
/// Query answer and authority sections are rejected. The additional section is
/// restricted to at most one structurally valid EDNS OPT record.
pub fn classify_query(message: &[u8]) -> Result<ClassifiedDnsQuery> {
    let parsed = parse_wire_question_header(message)?;
    if parsed.flags & 0x8000 != 0 {
        return Err(DnsError::NotAQuery);
    }
    if parsed.answer_count != 0 {
        return Err(DnsError::QueryContainsAnswers);
    }
    if parsed.authority_count != 0 {
        return Err(DnsError::QueryContainsAuthorityRecords);
    }
    if usize::from(parsed.additional_count) > 1 {
        return Err(DnsError::InvalidRecord);
    }

    let mut cursor = parsed.records_offset;
    for _ in 0..parsed.additional_count {
        let record = scan_record(message, &mut cursor)?;
        if record.record_type != TYPE_OPT || !record.owner.is_empty() {
            return Err(DnsError::InvalidRecord);
        }
        validate_edns_options(
            message,
            usize::from(record.data_start),
            usize::from(record.data_end),
        )?;
    }
    if cursor != message.len() {
        return Err(DnsError::TrailingData);
    }

    let kind = match parsed.question.query_type {
        1 => DnsQueryKind::Address(QueryType::A),
        28 => DnsQueryKind::Address(QueryType::Aaaa),
        _ => DnsQueryKind::Opaque,
    };
    let question_wire = encode_wire_question(&parsed.question);
    let semantics_digest = Sha256::digest(&message[2..]).into();
    Ok(ClassifiedDnsQuery {
        id: parsed.id,
        recursion_desired: parsed.flags & 0x0100 != 0,
        question: parsed.question,
        kind,
        question_wire,
        semantics_digest,
    })
}

/// Builds a response containing only the original encoded question. The
/// caller supplies a four-bit rcode; QR and RA are set, and the client's RD
/// bit is preserved.
pub fn synthesize_empty_response(query: &ClassifiedDnsQuery, rcode: u8) -> Result<Vec<u8>> {
    if rcode > 0x0f {
        return Err(DnsError::InvalidRcode);
    }
    let mut response = Vec::with_capacity(DNS_HEADER_LEN + query.question_wire.len());
    response.extend_from_slice(&query.id.to_be_bytes());
    let mut flags = 0x8000 | 0x0080 | u16::from(rcode); // QR | RA | RCODE
    if query.recursion_desired {
        flags |= 0x0100;
    }
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query.question_wire);
    Ok(response)
}

/// Builds a local SERVFAIL after all configured upstreams fail.
pub fn synthesize_servfail_response(query: &ClassifiedDnsQuery) -> Vec<u8> {
    synthesize_empty_response(query, 2).expect("SERVFAIL is a four-bit DNS rcode")
}

/// Performs a complete bounded scan of an opaque response and checks that it
/// belongs to `query`. Unknown RDATA stays opaque; every owner name, RR length,
/// section count and trailing byte is nevertheless validated before the wire
/// payload can enter [`OpaqueDnsCache`].
pub fn validate_opaque_response(
    query: &ClassifiedDnsQuery,
    response: &[u8],
) -> Result<ValidatedOpaqueResponse> {
    if !query.is_opaque() {
        return Err(DnsError::ExpectedOpaqueQuestion);
    }
    let parsed = parse_wire_question_header(response)?;
    if parsed.flags & 0x8000 == 0 {
        return Err(DnsError::NotAResponse);
    }
    if parsed.id != query.id || parsed.question != query.question {
        return Err(DnsError::ResponseMismatch);
    }
    if parsed.flags & 0x0200 != 0 {
        return Err(DnsError::TruncatedResponse);
    }

    let record_count = usize::from(parsed.answer_count)
        .checked_add(usize::from(parsed.authority_count))
        .and_then(|count| count.checked_add(usize::from(parsed.additional_count)))
        .ok_or(DnsError::TooManyRecords)?;
    if record_count > MAX_OPAQUE_RECORDS {
        return Err(DnsError::TooManyRecords);
    }

    let mut cursor = parsed.records_offset;
    let mut ttl_offsets = Vec::with_capacity(record_count);
    let mut minimum_ttl = None;
    let section_counts = [
        parsed.answer_count,
        parsed.authority_count,
        parsed.additional_count,
    ];
    let mut seen_opt = false;
    let mut extended_rcode = 0_u8;
    let mut authority_has_soa = false;
    for (section, count) in section_counts.into_iter().enumerate() {
        for _ in 0..count {
            let record = scan_record(response, &mut cursor)?;
            if section == 1
                && record.record_type == 6
                && record.record_class == query.question.query_class
            {
                authority_has_soa = true;
            }
            if record.record_type == TYPE_OPT {
                if section != 2 || seen_opt || !record.owner.is_empty() {
                    return Err(DnsError::InvalidRecord);
                }
                seen_opt = true;
                extended_rcode = (record.ttl >> 24) as u8;
                validate_edns_options(
                    response,
                    usize::from(record.data_start),
                    usize::from(record.data_end),
                )?;
            } else {
                ttl_offsets.push(record.ttl_offset);
                minimum_ttl =
                    Some(minimum_ttl.map_or(record.ttl, |value: u32| value.min(record.ttl)));
            }
        }
    }
    if cursor != response.len() {
        return Err(DnsError::TrailingData);
    }

    let header_rcode = (parsed.flags & 0x000f) as u8;
    let rcode = (u16::from(extended_rcode) << 4) | u16::from(header_rcode);
    let cache_policy = if extended_rcode != 0 {
        OpaqueCachePolicy::NotCacheable
    } else if header_rcode == RCODE_NXDOMAIN {
        OpaqueCachePolicy::Negative {
            lifetime_secs: NEGATIVE_TTL_SECS,
        }
    } else if header_rcode == RCODE_NOERROR && parsed.answer_count == 0 {
        if authority_has_soa {
            OpaqueCachePolicy::Negative {
                lifetime_secs: NEGATIVE_TTL_SECS,
            }
        } else {
            OpaqueCachePolicy::NotCacheable
        }
    } else if header_rcode == RCODE_NOERROR {
        match minimum_ttl {
            Some(0) | None => OpaqueCachePolicy::NotCacheable,
            Some(ttl) => OpaqueCachePolicy::Positive {
                lifetime_secs: clamp_ttl(ttl),
            },
        }
    } else {
        OpaqueCachePolicy::NotCacheable
    };

    Ok(ValidatedOpaqueResponse {
        wire: response.to_vec().into_boxed_slice(),
        question: parsed.question,
        semantics_digest: query.semantics_digest,
        ttl_offsets: ttl_offsets.into_boxed_slice(),
        rcode,
        cache_policy,
    })
}

/// Parses and validates a DNS query. Only opcode 0, class IN and A/AAAA are
/// accepted. Additional records (for example EDNS OPT) are bounded by the
/// message-size limit and validated structurally.
pub fn parse_query(message: &[u8]) -> Result<DnsMessage> {
    let parsed = parse_message(message)?;
    if parsed.is_response {
        return Err(DnsError::NotAQuery);
    }
    if parsed.answer_count != 0 {
        return Err(DnsError::QueryContainsAnswers);
    }
    Ok(parsed)
}

/// Parses and validates a DNS response with one A/AAAA question.
pub fn parse_response(message: &[u8]) -> Result<DnsMessage> {
    let parsed = parse_message(message)?;
    if !parsed.is_response {
        return Err(DnsError::NotAResponse);
    }
    if u16::from_be_bytes([message[2], message[3]]) & 0x0200 != 0 {
        return Err(DnsError::TruncatedResponse);
    }
    Ok(parsed)
}

/// Validates the response envelope before traversing its resource-record body.
/// Identity mismatches remain ignorable UDP noise; only a response belonging
/// to `query` can fail the current attempt because its TC flag is set.
pub(crate) fn validate_response_identity(query: &DnsMessage, response: &[u8]) -> Result<()> {
    let parsed = parse_question_header(response, false)?;
    if parsed.flags & 0x8000 == 0 {
        return Err(DnsError::NotAResponse);
    }
    if parsed.id != query.id || parsed.question != query.question {
        return Err(DnsError::ResponseMismatch);
    }
    if parsed.flags & 0x0200 != 0 {
        return Err(DnsError::TruncatedResponse);
    }
    Ok(())
}

fn parse_message(message: &[u8]) -> Result<DnsMessage> {
    let ParsedQuestionHeader {
        id,
        flags,
        answer_count,
        authority_count,
        additional_count,
        question,
        records_offset,
    } = parse_question_header(message, true)?;

    let mut cursor = records_offset;
    let mut answers = Vec::with_capacity(usize::from(answer_count).min(MAX_RESPONSE_RECORDS));
    for _ in 0..answer_count {
        if let Some(record) = parse_record(message, &mut cursor)? {
            answers.push(record);
        }
    }
    for _ in 0..authority_count {
        parse_record(message, &mut cursor)?;
    }
    for _ in 0..additional_count {
        parse_record(message, &mut cursor)?;
    }
    if cursor != message.len() {
        return Err(DnsError::TrailingData);
    }

    Ok(DnsMessage {
        id,
        is_response: flags & 0x8000 != 0,
        authoritative: flags & 0x0400 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        rcode: (flags & 0x000f) as u8,
        question,
        answers,
        answer_count,
    })
}

fn parse_question_header(
    message: &[u8],
    enforce_answer_limit: bool,
) -> Result<ParsedQuestionHeader> {
    let parsed = parse_wire_question_header_inner(message, enforce_answer_limit)?;
    let query_type = QueryType::from_wire(parsed.question.query_type)?;

    Ok(ParsedQuestionHeader {
        id: parsed.id,
        flags: parsed.flags,
        answer_count: parsed.answer_count,
        authority_count: parsed.authority_count,
        additional_count: parsed.additional_count,
        question: DnsQuestion {
            name: parsed.question.name,
            query_type,
        },
        records_offset: parsed.records_offset,
    })
}

fn parse_wire_question_header(message: &[u8]) -> Result<WireQuestionHeader> {
    parse_wire_question_header_inner(message, false)
}

fn parse_wire_question_header_inner(
    message: &[u8],
    enforce_answer_limit: bool,
) -> Result<WireQuestionHeader> {
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(DnsError::MessageTooLarge);
    }
    if message.len() < DNS_HEADER_LEN {
        return Err(DnsError::Truncated);
    }

    let id = read_u16(message, 0)?;
    let flags = read_u16(message, 2)?;
    let opcode = (flags >> 11) & 0x0f;
    if opcode != 0 {
        return Err(DnsError::UnsupportedOpcode);
    }
    // AD and CD are defined; the single remaining Z bit must stay zero.
    if flags & 0x0040 != 0 {
        return Err(DnsError::ReservedFlag);
    }

    let question_count = read_u16(message, 4)?;
    let answer_count = read_u16(message, 6)?;
    let authority_count = read_u16(message, 8)?;
    let additional_count = read_u16(message, 10)?;
    if question_count != 1 {
        return Err(DnsError::InvalidQuestionCount);
    }
    let record_count = usize::from(answer_count)
        .checked_add(usize::from(authority_count))
        .and_then(|count| count.checked_add(usize::from(additional_count)))
        .ok_or(DnsError::TooManyAnswers)?;
    if enforce_answer_limit && record_count > MAX_RESPONSE_RECORDS {
        return Err(DnsError::TooManyAnswers);
    }

    let mut cursor = DNS_HEADER_LEN;
    let (question_name, consumed) = decode_name(message, cursor)?;
    if question_name.is_empty() {
        return Err(DnsError::InvalidName);
    }
    cursor = cursor.checked_add(consumed).ok_or(DnsError::Truncated)?;
    let query_type = read_u16(message, cursor)?;
    cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let query_class = read_u16(message, cursor)?;
    if query_class != CLASS_IN {
        return Err(DnsError::UnsupportedQuestionClass);
    }
    cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;

    Ok(WireQuestionHeader {
        id,
        flags,
        answer_count,
        authority_count,
        additional_count,
        question: WireQuestion {
            name: question_name,
            query_type,
            query_class,
        },
        records_offset: cursor,
    })
}

fn scan_record(message: &[u8], cursor: &mut usize) -> Result<ScannedRecord> {
    let (owner, consumed) = decode_name(message, *cursor)?;
    *cursor = cursor.checked_add(consumed).ok_or(DnsError::Truncated)?;
    let record_type = read_u16(message, *cursor)?;
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let record_class = read_u16(message, *cursor)?;
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let ttl_offset = u16::try_from(*cursor).map_err(|_| DnsError::InvalidRecord)?;
    let ttl = read_u32(message, *cursor)?;
    *cursor = cursor.checked_add(4).ok_or(DnsError::Truncated)?;
    let data_len = usize::from(read_u16(message, *cursor)?);
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let data_start = u16::try_from(*cursor).map_err(|_| DnsError::InvalidRecord)?;
    *cursor = cursor
        .checked_add(data_len)
        .filter(|end| *end <= message.len())
        .ok_or(DnsError::Truncated)?;
    let data_end = u16::try_from(*cursor).map_err(|_| DnsError::InvalidRecord)?;
    Ok(ScannedRecord {
        owner,
        record_type,
        record_class,
        ttl,
        ttl_offset,
        data_start,
        data_end,
    })
}

fn validate_edns_options(message: &[u8], start: usize, end: usize) -> Result<()> {
    let mut cursor = start;
    while cursor < end {
        if end - cursor < 4 {
            return Err(DnsError::InvalidRecord);
        }
        read_u16(message, cursor)?; // option code
        cursor += 2;
        let option_len = usize::from(read_u16(message, cursor)?);
        cursor += 2;
        cursor = cursor
            .checked_add(option_len)
            .filter(|next| *next <= end)
            .ok_or(DnsError::InvalidRecord)?;
    }
    Ok(())
}

fn parse_record(message: &[u8], cursor: &mut usize) -> Result<Option<DnsRecord>> {
    let (name, consumed) = decode_name(message, *cursor)?;
    *cursor = cursor.checked_add(consumed).ok_or(DnsError::Truncated)?;
    let record_type = read_u16(message, *cursor)?;
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let class = read_u16(message, *cursor)?;
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let ttl = read_u32(message, *cursor)?;
    *cursor = cursor.checked_add(4).ok_or(DnsError::Truncated)?;
    let data_len = usize::from(read_u16(message, *cursor)?);
    *cursor = cursor.checked_add(2).ok_or(DnsError::Truncated)?;
    let data_start = *cursor;
    let data_end = data_start
        .checked_add(data_len)
        .filter(|end| *end <= message.len())
        .ok_or(DnsError::Truncated)?;

    let data = if class != CLASS_IN {
        None
    } else {
        match record_type {
            1 => {
                let octets: [u8; 4] = message[data_start..data_end]
                    .try_into()
                    .map_err(|_| DnsError::InvalidRecord)?;
                Some(RecordData::A(Ipv4Addr::from(octets)))
            }
            28 => {
                let octets: [u8; 16] = message[data_start..data_end]
                    .try_into()
                    .map_err(|_| DnsError::InvalidRecord)?;
                Some(RecordData::Aaaa(Ipv6Addr::from(octets)))
            }
            TYPE_CNAME => {
                let (target, cname_len) = decode_name(message, data_start)?;
                if target.is_empty() || cname_len != data_len {
                    return Err(DnsError::InvalidRecord);
                }
                Some(RecordData::Cname(target))
            }
            _ => None,
        }
    };
    *cursor = data_end;
    Ok(data.map(|data| DnsRecord { name, ttl, data }))
}

fn decode_name(message: &[u8], offset: usize) -> Result<(String, usize)> {
    if offset >= message.len() {
        return Err(DnsError::Truncated);
    }

    let mut cursor = offset;
    let mut consumed = 0_usize;
    let mut jumped = false;
    let mut jumps = 0_usize;
    let mut visited = [usize::MAX; MAX_COMPRESSION_JUMPS + 1];
    let mut visited_len = 1_usize;
    visited[0] = offset;
    let mut output = String::new();

    loop {
        let length = *message.get(cursor).ok_or(DnsError::Truncated)?;
        match length & 0xc0 {
            0xc0 => {
                let next = *message.get(cursor + 1).ok_or(DnsError::Truncated)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(next);
                if target >= message.len() {
                    return Err(DnsError::Truncated);
                }
                if visited[..visited_len].contains(&target) {
                    return Err(DnsError::CompressionPointerLoop);
                }
                if jumps >= MAX_COMPRESSION_JUMPS {
                    return Err(DnsError::TooManyCompressionJumps);
                }
                visited[visited_len] = target;
                visited_len += 1;
                jumps += 1;
                if !jumped {
                    consumed = consumed.checked_add(2).ok_or(DnsError::Truncated)?;
                }
                cursor = target;
                jumped = true;
            }
            0x00 => {
                let label_len = usize::from(length);
                if label_len == 0 {
                    if !jumped {
                        consumed = consumed.checked_add(1).ok_or(DnsError::Truncated)?;
                    }
                    break;
                }
                if label_len > 63 {
                    return Err(DnsError::InvalidName);
                }
                let label_start = cursor.checked_add(1).ok_or(DnsError::Truncated)?;
                let label_end = label_start
                    .checked_add(label_len)
                    .filter(|end| *end <= message.len())
                    .ok_or(DnsError::Truncated)?;
                let label = &message[label_start..label_end];
                if !label.iter().copied().all(valid_label_byte) {
                    return Err(DnsError::InvalidName);
                }
                let separator = usize::from(!output.is_empty());
                if output
                    .len()
                    .checked_add(separator + label_len)
                    .filter(|length| *length <= MAX_NAME_LEN)
                    .is_none()
                {
                    return Err(DnsError::NameTooLong);
                }
                if separator != 0 {
                    output.push('.');
                }
                // `valid_label_byte` guarantees ASCII and therefore UTF-8.
                output.extend(
                    label
                        .iter()
                        .map(|byte| char::from(byte.to_ascii_lowercase())),
                );
                if !jumped {
                    consumed = consumed
                        .checked_add(1 + label_len)
                        .ok_or(DnsError::Truncated)?;
                }
                cursor = label_end;
            }
            _ => return Err(DnsError::InvalidName),
        }
    }

    Ok((output, consumed))
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = message
        .get(offset..offset.saturating_add(2))
        .ok_or(DnsError::Truncated)?
        .try_into()
        .map_err(|_| DnsError::Truncated)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(message: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = message
        .get(offset..offset.saturating_add(4))
        .ok_or(DnsError::Truncated)?
        .try_into()
        .map_err(|_| DnsError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

fn encode_name(name: &str, output: &mut Vec<u8>) {
    for label in name.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
}

fn encode_wire_question(question: &WireQuestion) -> Box<[u8]> {
    let mut wire = Vec::with_capacity(question.name.len() + 6);
    encode_name(&question.name, &mut wire);
    wire.extend_from_slice(&question.query_type.to_be_bytes());
    wire.extend_from_slice(&question.query_class.to_be_bytes());
    wire.into_boxed_slice()
}

/// Normalizes an ASCII/IDNA A-label DNS name for matching and cache keys.
/// A single trailing root dot is accepted but not retained.
pub fn canonicalize_name(name: &str) -> Result<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DnsError::InvalidName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(DnsError::NameTooLong);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes().iter().copied().all(valid_label_byte)
        {
            return Err(DnsError::InvalidName);
        }
    }
    Ok(name.to_ascii_lowercase())
}

fn valid_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

#[must_use]
pub const fn clamp_ttl(ttl: u32) -> u32 {
    if ttl < MIN_TTL_SECS {
        MIN_TTL_SECS
    } else if ttl > MAX_TTL_SECS {
        MAX_TTL_SECS
    } else {
        ttl
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheValue {
    Positive(Vec<IpAddr>),
    /// `rcode == 0` represents a NODATA response; other values retain the
    /// four-bit DNS response code.
    Negative {
        rcode: u8,
    },
}

/// Single-owner result cache with a shared count for typed and opaque questions.
/// Lookups, recency updates and capacity eviction use a hash index and linked
/// slots; payloads remain bounded by their respective address/wire budgets.
#[derive(Debug)]
pub struct DnsCache {
    store: cache::Store,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_entries(MAX_CACHE_ENTRIES)
    }

    #[must_use]
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        Self {
            store: cache::Store::new(max_entries),
        }
    }

    #[must_use]
    pub(crate) fn with_algorithm(
        max_entries: usize,
        algorithm: crate::config::DnsCacheAlgorithm,
    ) -> Self {
        Self {
            store: cache::Store::with_algorithm(max_entries, algorithm),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        self.store.clear();
    }

    pub fn get(&mut self, name: &str, query_type: QueryType, now: Instant) -> Option<CacheValue> {
        self.get_with_ttl(name, query_type, now)
            .map(|(value, _remaining_ttl)| value)
    }

    /// Hits refresh recency without extending the entry's own expiry.
    pub fn get_with_ttl(
        &mut self,
        name: &str,
        query_type: QueryType,
        now: Instant,
    ) -> Option<(CacheValue, u32)> {
        let key = cache::Key::Address(canonicalize_name(name).ok()?, query_type);
        let (cache::Value::Address(value), expires_at) = self.store.get(&key, now)? else {
            return None;
        };
        Some((value.clone(), remaining_ttl(expires_at, now)))
    }

    pub fn insert_positive(
        &mut self,
        name: &str,
        query_type: QueryType,
        addresses: &[IpAddr],
        ttl: u32,
        now: Instant,
    ) -> Result<()> {
        if addresses.is_empty() {
            return Err(DnsError::EmptyCacheValue);
        }
        if addresses.len() > MAX_ANSWERS {
            return Err(DnsError::TooManyCacheAddresses);
        }
        if addresses.iter().any(|address| {
            !matches!(
                (query_type, address),
                (QueryType::A, IpAddr::V4(_)) | (QueryType::Aaaa, IpAddr::V6(_))
            )
        }) {
            return Err(DnsError::AddressFamilyMismatch);
        }
        self.insert(
            name,
            query_type,
            CacheValue::Positive(addresses.to_vec()),
            clamp_ttl(ttl),
            now,
        )
    }

    pub fn insert_negative(
        &mut self,
        name: &str,
        query_type: QueryType,
        rcode: u8,
        now: Instant,
    ) -> Result<()> {
        if rcode > 0x0f {
            return Err(DnsError::InvalidRcode);
        }
        self.insert(
            name,
            query_type,
            CacheValue::Negative { rcode },
            NEGATIVE_TTL_SECS,
            now,
        )
    }

    fn insert(
        &mut self,
        name: &str,
        query_type: QueryType,
        value: CacheValue,
        ttl: u32,
        now: Instant,
    ) -> Result<()> {
        self.store.insert(
            cache::Key::Address(canonicalize_name(name)?, query_type),
            cache::Value::Address(value),
            expiry(now, ttl),
            now,
        )
    }

    /// An opaque hit restores the caller's ID/RD and remaining record TTLs.
    pub(crate) fn get_opaque(
        &mut self,
        query: &ClassifiedDnsQuery,
        now: Instant,
    ) -> Option<Vec<u8>> {
        if !query.is_opaque() {
            return None;
        }
        let key = cache::Key::Opaque(query.question.clone(), query.semantics_digest);
        let (
            cache::Value::Opaque {
                wire, ttl_offsets, ..
            },
            expires_at,
        ) = self.store.get(&key, now)?
        else {
            return None;
        };
        let mut wire = wire.to_vec();
        wire[..2].copy_from_slice(&query.id.to_be_bytes());
        let mut flags = u16::from_be_bytes([wire[2], wire[3]]);
        if query.recursion_desired {
            flags |= 0x0100;
        } else {
            flags &= !0x0100;
        }
        wire[2..4].copy_from_slice(&flags.to_be_bytes());
        let ttl = remaining_ttl(expires_at, now).to_be_bytes();
        for offset in ttl_offsets {
            let offset = usize::from(*offset);
            wire[offset..offset + 4].copy_from_slice(&ttl);
        }
        Some(wire)
    }

    /// Opaque payloads share the role's result count while retaining their own
    /// 64-response, 256 KiB, 4096-byte and 64-record safety boundaries.
    pub(crate) fn insert_opaque(
        &mut self,
        response: &ValidatedOpaqueResponse,
        now: Instant,
    ) -> bool {
        let Some(lifetime_secs) = response.cache_policy.lifetime_secs() else {
            return false;
        };
        let Some(accounted_bytes) = opaque_entry_accounted_bytes(response) else {
            return false;
        };
        if response.wire.len() > MAX_OPAQUE_CACHE_ENTRY_BYTES
            || accounted_bytes > MAX_OPAQUE_CACHE_BYTES
            || response.ttl_offsets.len() > MAX_OPAQUE_RECORDS
        {
            return false;
        }
        self.store
            .insert(
                cache::Key::Opaque(response.question.clone(), response.semantics_digest),
                cache::Value::Opaque {
                    wire: response.wire.clone(),
                    ttl_offsets: response.ttl_offsets.clone(),
                    accounted_bytes,
                },
                expiry(now, lifetime_secs),
                now,
            )
            .is_ok()
    }
}

fn remaining_ttl(expires_at: Instant, now: Instant) -> u32 {
    expires_at
        .saturating_duration_since(now)
        .as_secs()
        .min(u64::from(u32::MAX)) as u32
}

fn opaque_entry_accounted_bytes(response: &ValidatedOpaqueResponse) -> Option<usize> {
    response
        .wire
        .len()
        .checked_add(response.question.name.len())?
        .checked_add(4)? // qtype + qclass
        .checked_add(response.semantics_digest.len())?
        .checked_add(
            response
                .ttl_offsets
                .len()
                .checked_mul(std::mem::size_of::<u16>())?,
        )?
        .checked_add(cache::opaque_metadata_bytes())
}

/// Standalone opaque-only view of the same bounded result store.
/// Runtime roles use DnsCache directly so all question types share capacity.
#[derive(Debug)]
pub struct OpaqueDnsCache {
    cache: DnsCache,
}

impl Default for OpaqueDnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueDnsCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: DnsCache::with_max_entries(MAX_OPAQUE_CACHE_ENTRIES),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.store.opaque_len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.cache.store.opaque_bytes()
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn get(&mut self, query: &ClassifiedDnsQuery, now: Instant) -> Option<Vec<u8>> {
        self.cache.get_opaque(query, now)
    }

    pub fn insert(&mut self, response: &ValidatedOpaqueResponse, now: Instant) -> bool {
        self.cache.insert_opaque(response, now)
    }
}

#[derive(Debug)]
struct RedirHostEntry {
    address: IpAddr,
    domain: String,
    expires_at: Instant,
    sequence: u64,
}

/// Fixed-capacity reverse hint table used by redir-host routing. This is not a
/// general reverse-DNS cache: values are only populated from successful
/// forward lookups handled by the local DNS runtime.
#[derive(Debug)]
pub struct RedirHostHints {
    entries: Vec<RedirHostEntry>,
    max_entries: usize,
    next_sequence: u64,
}

impl Default for RedirHostHints {
    fn default() -> Self {
        Self::new()
    }
}

impl RedirHostHints {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_entries(MAX_REDIR_HOST_ENTRIES)
    }

    #[must_use]
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        assert!(
            max_entries != 0,
            "redir-host hint capacity must be non-zero"
        );
        Self {
            entries: Vec::new(),
            max_entries,
            next_sequence: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn get(&mut self, address: IpAddr, now: Instant) -> Option<String> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.address == address)?;
        if self.entries[index].expires_at <= now {
            self.entries.swap_remove(index);
            return None;
        }
        Some(self.entries[index].domain.clone())
    }

    pub fn insert(&mut self, address: IpAddr, domain: &str, ttl: u32, now: Instant) -> Result<()> {
        let domain = canonicalize_name(domain)?;
        self.remove_expired(now);
        let expires_at = expiry(now, clamp_ttl(ttl));
        let sequence = self.take_sequence();

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            *entry = RedirHostEntry {
                address,
                domain,
                expires_at,
                sequence,
            };
            return Ok(());
        }

        if self.entries.len() >= self.max_entries {
            let index = eviction_index(&self.entries, |entry| (entry.expires_at, entry.sequence));
            self.entries.swap_remove(index);
        }
        reserve_entry_slot(&mut self.entries, self.max_entries)?;
        self.entries.push(RedirHostEntry {
            address,
            domain,
            expires_at,
            sequence,
        });
        debug_assert!(self.entries.len() <= self.max_entries);
        Ok(())
    }

    fn remove_expired(&mut self, now: Instant) {
        self.entries.retain(|entry| entry.expires_at > now);
    }

    fn take_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }
}

fn expiry(now: Instant, ttl: u32) -> Instant {
    now.checked_add(Duration::from_secs(u64::from(ttl)))
        .unwrap_or(now)
}

fn reserve_entry_slot<T>(entries: &mut Vec<T>, max_entries: usize) -> Result<()> {
    if entries.len() >= max_entries {
        return Err(DnsError::CacheAllocation);
    }
    if entries.len() != entries.capacity() {
        return Ok(());
    }

    // Grow geometrically, but never request storage beyond the logical cache
    // limit. This keeps construction lazy without reallocating for every
    // inserted record.
    let remaining = max_entries - entries.len();
    let growth = entries.capacity().max(8).min(remaining);
    entries
        .try_reserve_exact(growth)
        .map_err(|_| DnsError::CacheAllocation)
}

fn eviction_index<T, F>(entries: &[T], key: F) -> usize
where
    F: Fn(&T) -> (Instant, u64),
{
    entries
        .iter()
        .enumerate()
        .min_by_key(|(_, entry)| key(entry))
        .map_or(0, |(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_for(name: &str, query_type: QueryType, answer_count: u16) -> Vec<u8> {
        let mut response = build_query(0x1234, name, query_type).unwrap();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());
        response
    }

    fn append_record(message: &mut Vec<u8>, owner: &[u8], record_type: u16, ttl: u32, data: &[u8]) {
        message.extend_from_slice(owner);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&(data.len() as u16).to_be_bytes());
        message.extend_from_slice(data);
    }

    fn wire_query(id: u16, name: &str, query_type: u16) -> Vec<u8> {
        let mut query = build_query(id, name, QueryType::A).unwrap();
        let type_offset = query.len() - 4;
        query[type_offset..type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
        query
    }

    fn opaque_response(query: &[u8], rcode: u8, truncated: bool) -> Vec<u8> {
        let query = classify_query(query).unwrap();
        let mut response = synthesize_empty_response(&query, rcode).unwrap();
        if truncated {
            let flags = u16::from_be_bytes([response[2], response[3]]) | 0x0200;
            response[2..4].copy_from_slice(&flags.to_be_bytes());
        }
        response
    }

    fn append_wire_record(
        message: &mut Vec<u8>,
        owner: &[u8],
        record_type: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> usize {
        message.extend_from_slice(owner);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&class.to_be_bytes());
        let ttl_offset = message.len();
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&(data.len() as u16).to_be_bytes());
        message.extend_from_slice(data);
        ttl_offset
    }

    fn set_counts(message: &mut [u8], answers: u16, authority: u16, additional: u16) {
        message[6..8].copy_from_slice(&answers.to_be_bytes());
        message[8..10].copy_from_slice(&authority.to_be_bytes());
        message[10..12].copy_from_slice(&additional.to_be_bytes());
    }

    #[test]
    fn query_builder_canonicalizes_and_parses_one_question() {
        let query = build_query(7, "WWW.Example.COM.", QueryType::Aaaa).unwrap();
        let parsed = parse_query(&query).unwrap();
        assert_eq!(parsed.id, 7);
        assert!(!parsed.is_response);
        assert!(parsed.recursion_desired);
        assert_eq!(parsed.question.name, "www.example.com");
        assert_eq!(parsed.question.query_type, QueryType::Aaaa);
        assert_eq!(parsed.answer_count, 0);
    }

    #[test]
    fn parses_compressed_a_and_aaaa_answers() {
        let mut a_response = response_for("example.com", QueryType::A, 1);
        append_record(&mut a_response, &[0xc0, 0x0c], 1, 90, &[192, 0, 2, 1]);
        let parsed = parse_response(&a_response).unwrap();
        assert_eq!(
            parsed.answers,
            vec![DnsRecord {
                name: "example.com".to_owned(),
                ttl: 90,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
            }]
        );

        let mut aaaa_response = response_for("example.com", QueryType::Aaaa, 1);
        let address = Ipv6Addr::LOCALHOST;
        append_record(
            &mut aaaa_response,
            &[0xc0, 0x0c],
            28,
            120,
            &address.octets(),
        );
        let parsed = parse_response(&aaaa_response).unwrap();
        assert_eq!(parsed.answers[0].data, RecordData::Aaaa(address));
    }

    #[test]
    fn parses_cname_with_a_compressed_suffix() {
        let mut response = response_for("alias.example.com", QueryType::A, 1);
        // "example" starts after the query's one-byte `alias` length and label.
        let cname = [4, b'r', b'e', b'a', b'l', 0xc0, 0x12];
        append_record(&mut response, &[0xc0, 0x0c], TYPE_CNAME, 45, &cname);
        let parsed = parse_response(&response).unwrap();
        assert_eq!(
            parsed.answers[0],
            DnsRecord {
                name: "alias.example.com".to_owned(),
                ttl: 45,
                data: RecordData::Cname("real.example.com".to_owned()),
            }
        );
    }

    #[test]
    fn rejects_tc_responses_without_reinterpreting_them_as_nodata() {
        let mut response = response_for("example.com", QueryType::A, 0);
        response[2..4].copy_from_slice(&0x8383_u16.to_be_bytes());
        assert_eq!(parse_response(&response), Err(DnsError::TruncatedResponse));
    }

    #[test]
    fn rejects_malformed_records_and_oversize_messages() {
        let mut response = response_for("example.com", QueryType::A, 1);
        append_record(&mut response, &[0xc0, 0x0c], 1, 60, &[1, 2, 3]);
        assert_eq!(parse_response(&response), Err(DnsError::InvalidRecord));

        assert_eq!(
            parse_response(&vec![0; MAX_MESSAGE_SIZE + 1]),
            Err(DnsError::MessageTooLarge)
        );

        let mut too_many = response_for(
            "example.com",
            QueryType::A,
            (MAX_RESPONSE_RECORDS + 1) as u16,
        );
        for index in 0..=MAX_RESPONSE_RECORDS {
            append_record(
                &mut too_many,
                &[0xc0, 0x0c],
                1,
                60,
                &[192, 0, 2, index as u8],
            );
        }
        assert_eq!(parse_response(&too_many), Err(DnsError::TooManyAnswers));
    }

    #[test]
    fn typed_response_scans_sixty_four_records_and_rejects_sixty_five() {
        let mut maximum = response_for("many.example", QueryType::A, MAX_RESPONSE_RECORDS as u16);
        for index in 0..MAX_RESPONSE_RECORDS {
            append_record(
                &mut maximum,
                &[0xc0, 0x0c],
                1,
                60,
                &[192, 0, index as u8, 1],
            );
        }
        let parsed = parse_response(&maximum).unwrap();
        assert_eq!(usize::from(parsed.answer_count), MAX_RESPONSE_RECORDS);
        assert_eq!(parsed.answers.len(), MAX_RESPONSE_RECORDS);

        let mut excessive = maximum;
        excessive[6..8].copy_from_slice(&((MAX_RESPONSE_RECORDS + 1) as u16).to_be_bytes());
        append_record(&mut excessive, &[0xc0, 0x0c], 1, 60, &[192, 0, 64, 1]);
        assert_eq!(parse_response(&excessive), Err(DnsError::TooManyAnswers));
    }

    #[test]
    fn rejects_compression_loops_out_of_bounds_and_excessive_depth() {
        assert_eq!(
            decode_name(&[0xc0, 0x00], 0),
            Err(DnsError::CompressionPointerLoop)
        );
        assert_eq!(decode_name(&[0xc0, 0xff], 0), Err(DnsError::Truncated));

        let mut chain = vec![0_u8; (MAX_COMPRESSION_JUMPS + 1) * 2 + 1];
        for jump in 0..=MAX_COMPRESSION_JUMPS {
            let target = (jump + 1) * 2;
            chain[jump * 2] = 0xc0 | ((target >> 8) as u8 & 0x3f);
            chain[jump * 2 + 1] = target as u8;
        }
        assert_eq!(
            decode_name(&chain, 0),
            Err(DnsError::TooManyCompressionJumps)
        );
    }

    #[test]
    fn rejects_multiple_questions_and_trailing_data() {
        let mut query = build_query(1, "example.com", QueryType::A).unwrap();
        query[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(parse_query(&query), Err(DnsError::InvalidQuestionCount));

        let mut query = build_query(1, "example.com", QueryType::A).unwrap();
        query.push(0);
        assert_eq!(parse_query(&query), Err(DnsError::TrailingData));
    }

    #[test]
    fn cache_clamps_positive_and_negative_ttls() {
        let now = Instant::now();
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let mut cache = DnsCache::new();

        cache
            .insert_positive("MIN.example", QueryType::A, &[address], 1, now)
            .unwrap();
        assert!(
            cache
                .get(
                    "min.example",
                    QueryType::A,
                    now + Duration::from_secs(MIN_TTL_SECS.into()) - Duration::from_millis(1)
                )
                .is_some()
        );
        assert_eq!(
            cache.get(
                "min.example",
                QueryType::A,
                now + Duration::from_secs(MIN_TTL_SECS.into())
            ),
            None
        );

        cache
            .insert_positive("max.example", QueryType::A, &[address], u32::MAX, now)
            .unwrap();
        assert!(
            cache
                .get(
                    "max.example",
                    QueryType::A,
                    now + Duration::from_secs(u64::from(MAX_TTL_SECS - 1))
                )
                .is_some()
        );
        assert_eq!(
            cache.get(
                "max.example",
                QueryType::A,
                now + Duration::from_secs(MAX_TTL_SECS.into())
            ),
            None
        );

        cache
            .insert_negative("missing.example", QueryType::A, 3, now)
            .unwrap();
        assert_eq!(
            cache.get(
                "missing.example",
                QueryType::A,
                now + Duration::from_secs(NEGATIVE_TTL_SECS.into())
            ),
            None
        );
    }

    #[test]
    fn cache_is_fixed_capacity_and_evicts_the_least_recent_entry() {
        let now = Instant::now();
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut cache = DnsCache::new();
        for index in 0..MAX_CACHE_ENTRIES {
            cache
                .insert_positive(
                    &format!("host{index}.example"),
                    QueryType::A,
                    &[address],
                    60,
                    now,
                )
                .unwrap();
        }
        cache
            .insert_positive("new.example", QueryType::A, &[address], 60, now)
            .unwrap();

        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        assert_eq!(cache.get("host0.example", QueryType::A, now), None);
        assert!(cache.get("new.example", QueryType::A, now).is_some());
    }

    #[test]
    fn cache_uses_runtime_capacity_and_allocates_on_first_insert() {
        let now = Instant::now();
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut cache = DnsCache::with_max_entries(2);
        assert_eq!(cache.store.allocated_slots(), 0);

        for name in ["first.example", "second.example", "third.example"] {
            cache
                .insert_positive(name, QueryType::A, &[address], 60, now)
                .unwrap();
        }

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("first.example", QueryType::A, now), None);
        assert!(cache.get("third.example", QueryType::A, now).is_some());
    }

    #[test]
    fn cache_lru_hits_and_replacements_preserve_ttl_and_promote_entries() {
        let now = Instant::now();
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut cache = DnsCache::with_max_entries(2);
        cache
            .insert_positive("short.example", QueryType::A, &[address], 30, now)
            .unwrap();
        cache
            .insert_negative("negative.example", QueryType::Aaaa, 3, now)
            .unwrap();
        assert_eq!(
            cache.get_with_ttl(
                "SHORT.example.",
                QueryType::A,
                now + Duration::from_secs(10)
            ),
            Some((CacheValue::Positive(vec![address]), 20))
        );
        cache
            .insert_positive("long.example", QueryType::A, &[address], 3600, now)
            .unwrap();
        assert_eq!(cache.get("negative.example", QueryType::Aaaa, now), None);
        // Updating the short entry is also a use, independent of its expiry.
        cache
            .insert_negative("short.example", QueryType::A, 0, now)
            .unwrap();
        cache
            .insert_negative("other.example", QueryType::A, 3, now)
            .unwrap();
        assert_eq!(cache.get("long.example", QueryType::A, now), None);
        assert_eq!(
            cache.get("short.example", QueryType::A, now),
            Some(CacheValue::Negative { rcode: 0 })
        );
        assert_eq!(
            cache.get("short.example", QueryType::A, now + Duration::from_secs(30)),
            None
        );
        // Freed slots are reused, and clear releases all retained allocation.
        for index in 0..100 {
            cache
                .insert_negative(&format!("cycle{index}.example"), QueryType::A, 3, now)
                .unwrap();
        }
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.store.allocated_slots(), 2);
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.store.allocated_slots(), 0);
    }

    #[test]
    fn cache_shares_typed_and_opaque_capacity_and_reclaims_opaque_bytes() {
        let now = Instant::now();
        let mut cache = DnsCache::with_max_entries(2);
        let query_wire = wire_query(1, "opaque.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 1, 0, 0);
        append_wire_record(&mut response, &[0xc0, 0x0c], 16, CLASS_IN, 60, &[]);
        let response = validate_opaque_response(&query, &response).unwrap();
        cache
            .insert_negative("typed.example", QueryType::A, 3, now)
            .unwrap();
        assert!(cache.insert_opaque(&response, now));
        assert!(cache.store.opaque_bytes() > 0);
        assert!(cache.get("typed.example", QueryType::A, now).is_some());
        cache
            .insert_negative("next.example", QueryType::A, 3, now)
            .unwrap();
        assert_eq!(cache.get_opaque(&query, now), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.store.opaque_bytes(), 0);
        assert!(cache.insert_opaque(&response, now));
        assert_eq!(
            cache.get_opaque(&query, now + Duration::from_secs(60)),
            None
        );
        assert_eq!(cache.store.opaque_bytes(), 0);
    }

    #[test]
    fn cache_rejects_unbounded_or_mismatched_values() {
        let now = Instant::now();
        let mut cache = DnsCache::new();
        let oversized = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); MAX_ANSWERS + 1];
        assert_eq!(
            cache.insert_positive("example.com", QueryType::A, &oversized, 60, now),
            Err(DnsError::TooManyCacheAddresses)
        );
        assert_eq!(
            cache.insert_positive(
                "example.com",
                QueryType::A,
                &[IpAddr::V6(Ipv6Addr::LOCALHOST)],
                60,
                now
            ),
            Err(DnsError::AddressFamilyMismatch)
        );
    }

    #[test]
    fn redir_host_hints_are_ttl_bounded_and_fixed_capacity() {
        let now = Instant::now();
        let mut hints = RedirHostHints::new();
        for index in 0..MAX_REDIR_HOST_ENTRIES {
            let address = IpAddr::V6(Ipv6Addr::from(index as u128 + 1));
            hints
                .insert(address, &format!("host{index}.example"), 1, now)
                .unwrap();
        }
        let new_address = IpAddr::V6(Ipv6Addr::from(1_000_u128));
        hints.insert(new_address, "New.Example.", 1, now).unwrap();

        assert_eq!(hints.len(), MAX_REDIR_HOST_ENTRIES);
        assert_eq!(hints.get(IpAddr::V6(Ipv6Addr::from(1_u128)), now), None);
        assert_eq!(hints.get(new_address, now), Some("new.example".to_owned()));
        assert_eq!(
            hints.get(new_address, now + Duration::from_secs(MIN_TTL_SECS.into())),
            None
        );
    }

    #[test]
    fn redir_host_hints_use_runtime_capacity_and_allocate_lazily() {
        let now = Instant::now();
        let mut hints = RedirHostHints::with_max_entries(2);
        assert_eq!(hints.entries.capacity(), 0);

        for index in 1..=3 {
            hints
                .insert(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, index)),
                    &format!("host{index}.example"),
                    60,
                    now,
                )
                .unwrap();
        }

        assert_eq!(hints.len(), 2);
        assert_eq!(
            hints.get(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), now),
            None
        );
        assert_eq!(
            hints.get(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), now),
            Some("host3.example".to_owned())
        );
    }

    #[test]
    fn redir_host_lookup_checks_only_the_matching_expiration() {
        let now = Instant::now();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let replacement = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let mut hints = RedirHostHints::with_max_entries(2);
        hints.insert(first, "first.example", 1, now).unwrap();
        hints.insert(second, "second.example", 1, now).unwrap();

        let expired = now + Duration::from_secs(MIN_TTL_SECS.into());
        assert_eq!(hints.get(first, expired), None);
        assert_eq!(
            hints.len(),
            1,
            "lookup must not scan and retain-filter unrelated entries"
        );

        hints
            .insert(replacement, "replacement.example", 60, expired)
            .unwrap();
        assert_eq!(
            hints.len(),
            1,
            "insertion remains responsible for the full expiration sweep"
        );
        assert_eq!(
            hints.get(replacement, expired),
            Some("replacement.example".to_owned())
        );
    }

    #[test]
    fn classifier_preserves_every_wire_qtype_and_keeps_address_types_typed() {
        for query_type in [0, 2, 5, 6, 12, 15, 16, 33, 43, 46, 48, 64, 65, 255, 65_535] {
            let query = wire_query(7, "Service.Example.", query_type);
            let classified = classify_query(&query).unwrap();
            assert_eq!(classified.id, 7);
            assert_eq!(classified.question.name, "service.example");
            assert_eq!(classified.question.query_type, query_type);
            assert_eq!(classified.question.query_class, CLASS_IN);
            assert_eq!(classified.kind, DnsQueryKind::Opaque);
            assert_eq!(parse_query(&query), Err(DnsError::UnsupportedQuestionType));
        }

        let a = classify_query(&wire_query(1, "a.example", 1)).unwrap();
        assert_eq!(a.kind, DnsQueryKind::Address(QueryType::A));
        let aaaa = classify_query(&wire_query(2, "aaaa.example", 28)).unwrap();
        assert_eq!(aaaa.kind, DnsQueryKind::Address(QueryType::Aaaa));
    }

    #[test]
    fn classifier_accepts_one_edns_record_and_rejects_invalid_query_sections() {
        let mut edns = wire_query(1, "example.com", 16);
        edns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_wire_record(&mut edns, &[0], TYPE_OPT, 1232, 0x0000_8000, &[]);
        let classified = classify_query(&edns).unwrap();
        assert_eq!(classified.question_wire(), &edns[DNS_HEADER_LEN..29]);

        let mut answer = wire_query(1, "example.com", 16);
        answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(classify_query(&answer), Err(DnsError::QueryContainsAnswers));

        let mut authority = wire_query(1, "example.com", 16);
        authority[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            classify_query(&authority),
            Err(DnsError::QueryContainsAuthorityRecords)
        );

        let mut non_in = wire_query(1, "example.com", 16);
        let class_offset = non_in.len() - 2;
        non_in[class_offset..].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            classify_query(&non_in),
            Err(DnsError::UnsupportedQuestionClass)
        );

        let mut non_opt = wire_query(1, "example.com", 16);
        non_opt[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_wire_record(&mut non_opt, &[0], 16, CLASS_IN, 0, &[]);
        assert_eq!(classify_query(&non_opt), Err(DnsError::InvalidRecord));

        let mut malformed_edns = wire_query(1, "example.com", 16);
        malformed_edns[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_wire_record(
            &mut malformed_edns,
            &[0],
            TYPE_OPT,
            1232,
            0,
            &[0, 1, 0, 2, 0],
        );
        assert_eq!(
            classify_query(&malformed_edns),
            Err(DnsError::InvalidRecord)
        );

        let mut trailing = wire_query(1, "example.com", 16);
        trailing.push(0);
        assert_eq!(classify_query(&trailing), Err(DnsError::TrailingData));
    }

    #[test]
    fn synthetic_response_reencodes_a_question_that_points_into_edns() {
        let mut query = Vec::new();
        query.extend_from_slice(&7_u16.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0xc0, 33]); // EDNS option data starts at offset 33.
        query.extend_from_slice(&16_u16.to_be_bytes());
        query.extend_from_slice(&CLASS_IN.to_be_bytes());
        let mut option = vec![0, 1, 0, 13];
        encode_name("example.com", &mut option);
        append_wire_record(&mut query, &[0], TYPE_OPT, 1232, 0, &option);

        let classified = classify_query(&query).unwrap();
        assert_eq!(classified.question.name, "example.com");
        assert_ne!(classified.question_wire()[0] & 0xc0, 0xc0);

        let response = synthesize_servfail_response(&classified);
        assert_eq!(response.len(), DNS_HEADER_LEN + 17);
        assert_eq!(&response[DNS_HEADER_LEN..], classified.question_wire());
        assert_eq!(
            validate_opaque_response(&classified, &response)
                .unwrap()
                .rcode(),
            2
        );
    }

    #[test]
    fn opaque_response_scanner_validates_identity_counts_lengths_and_compression() {
        let query_wire = wire_query(0x1234, "example.com", 65);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 1, 1, 1);
        append_wire_record(&mut response, &[0xc0, 0x0c], 65, CLASS_IN, 120, &[1, 2]);
        append_wire_record(&mut response, &[0xc0, 0x0c], 6, CLASS_IN, 40, &[]);
        append_wire_record(&mut response, &[0], TYPE_OPT, 1232, 0x0000_8000, &[]);

        let validated = validate_opaque_response(&query, &response).unwrap();
        assert_eq!(validated.wire(), response);
        assert_eq!(
            validated.cache_policy(),
            OpaqueCachePolicy::Positive { lifetime_secs: 40 }
        );

        let mut wrong_id = response.clone();
        wrong_id[..2].copy_from_slice(&0x4321_u16.to_be_bytes());
        assert_eq!(
            validate_opaque_response(&query, &wrong_id),
            Err(DnsError::ResponseMismatch)
        );

        let mut query_flag = response.clone();
        query_flag[2] &= 0x7f;
        assert_eq!(
            validate_opaque_response(&query, &query_flag),
            Err(DnsError::NotAResponse)
        );

        let mut trailing = response.clone();
        trailing.push(0);
        assert_eq!(
            validate_opaque_response(&query, &trailing),
            Err(DnsError::TrailingData)
        );

        let mut too_many = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut too_many, (MAX_OPAQUE_RECORDS + 1) as u16, 0, 0);
        assert_eq!(
            validate_opaque_response(&query, &too_many),
            Err(DnsError::TooManyRecords)
        );

        let mut compression_loop = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut compression_loop, 1, 0, 0);
        let owner_offset = compression_loop.len();
        let pointer = [
            0xc0 | ((owner_offset >> 8) as u8 & 0x3f),
            owner_offset as u8,
        ];
        append_wire_record(&mut compression_loop, &pointer, 65, CLASS_IN, 60, &[]);
        assert_eq!(
            validate_opaque_response(&query, &compression_loop),
            Err(DnsError::CompressionPointerLoop)
        );

        let mut opt_in_answer = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut opt_in_answer, 1, 0, 0);
        append_wire_record(&mut opt_in_answer, &[0], TYPE_OPT, 1232, 0, &[]);
        assert_eq!(
            validate_opaque_response(&query, &opt_in_answer),
            Err(DnsError::InvalidRecord)
        );
    }

    #[test]
    fn opaque_extended_rcode_is_effective_and_never_negative_cached() {
        let query_wire = wire_query(1, "badvers.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 0, 0, 1);
        append_wire_record(&mut response, &[0], TYPE_OPT, 1232, 1_u32 << 24, &[]);

        let validated = validate_opaque_response(&query, &response).unwrap();
        assert_eq!(validated.rcode(), 16); // BADVERS
        assert_eq!(validated.cache_policy(), OpaqueCachePolicy::NotCacheable);
        assert!(!OpaqueDnsCache::new().insert(&validated, Instant::now()));
    }

    #[test]
    fn empty_responses_cover_servfail_and_reject_invalid_rcode() {
        let query_wire = wire_query(0xabcd, "txt.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let servfail = synthesize_servfail_response(&query);
        assert_eq!(
            validate_opaque_response(&query, &servfail).unwrap().rcode(),
            2
        );
        assert_eq!(&servfail[DNS_HEADER_LEN..], query.question_wire());
        assert_eq!(
            synthesize_empty_response(&query, 16),
            Err(DnsError::InvalidRcode)
        );
    }

    #[test]
    fn opaque_cache_rewrites_id_and_all_non_opt_ttls() {
        let now = Instant::now();
        let query_wire = wire_query(0x1111, "txt.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 1, 1, 1);
        let answer_ttl =
            append_wire_record(&mut response, &[0xc0, 0x0c], 16, CLASS_IN, 120, b"payload");
        let authority_ttl = append_wire_record(&mut response, &[0xc0, 0x0c], 6, CLASS_IN, 45, &[]);
        let opt_ttl = append_wire_record(&mut response, &[0], TYPE_OPT, 1232, 0x0000_8000, &[]);
        let validated = validate_opaque_response(&query, &response).unwrap();
        assert_eq!(
            validated.cache_policy(),
            OpaqueCachePolicy::Positive { lifetime_secs: 45 }
        );

        let mut cache = OpaqueDnsCache::new();
        assert!(cache.insert(&validated, now));
        assert_eq!(cache.len(), 1);
        assert!(cache.retained_bytes() >= response.len());
        assert!(cache.retained_bytes() <= MAX_OPAQUE_CACHE_BYTES);

        let hit_query = classify_query(&wire_query(0x2222, "txt.example", 16)).unwrap();
        let hit = cache
            .get(&hit_query, now + Duration::from_secs(10))
            .unwrap();
        assert_eq!(read_u16(&hit, 0).unwrap(), 0x2222);
        assert_eq!(read_u32(&hit, answer_ttl).unwrap(), 35);
        assert_eq!(read_u32(&hit, authority_ttl).unwrap(), 35);
        assert_eq!(read_u32(&hit, opt_ttl).unwrap(), 0x0000_8000);
        assert_eq!(cache.get(&hit_query, now + Duration::from_secs(45)), None);
        assert_eq!(cache.retained_bytes(), 0);
    }

    #[test]
    fn opaque_cache_key_covers_flags_and_complete_edns_semantics() {
        let now = Instant::now();
        let query_wire = wire_query(1, "variant.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 1, 0, 0);
        append_wire_record(&mut response, &[0xc0, 0x0c], 16, CLASS_IN, 60, b"value");
        // A cache hit must restore the current request's RD even if an upstream
        // failed to echo it.
        response[2] &= !0x01;
        let validated = validate_opaque_response(&query, &response).unwrap();
        let mut cache = OpaqueDnsCache::new();
        assert!(cache.insert(&validated, now));

        let same_semantics = classify_query(&wire_query(2, "variant.example", 16)).unwrap();
        let hit = cache.get(&same_semantics, now).unwrap();
        assert_ne!(read_u16(&hit, 2).unwrap() & 0x0100, 0);

        let mut no_rd_wire = wire_query(3, "variant.example", 16);
        no_rd_wire[2..4].copy_from_slice(&0_u16.to_be_bytes());
        let no_rd = classify_query(&no_rd_wire).unwrap();
        assert_eq!(cache.get(&no_rd, now), None);

        let mut checking_disabled_wire = wire_query(4, "variant.example", 16);
        checking_disabled_wire[2..4].copy_from_slice(&0x0110_u16.to_be_bytes());
        let checking_disabled = classify_query(&checking_disabled_wire).unwrap();
        assert_eq!(cache.get(&checking_disabled, now), None);

        let mut edns_wire = wire_query(5, "variant.example", 16);
        edns_wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_wire_record(&mut edns_wire, &[0], TYPE_OPT, 1232, 0x0000_8000, &[]);
        let edns = classify_query(&edns_wire).unwrap();
        assert_eq!(cache.get(&edns, now), None);
    }

    #[test]
    fn opaque_cache_applies_fixed_negative_lifetime_and_rejects_uncacheable() {
        let now = Instant::now();
        let query_wire = wire_query(1, "missing.example", 16);
        let query = classify_query(&query_wire).unwrap();

        let mut nxdomain = opaque_response(&query_wire, RCODE_NXDOMAIN, false);
        set_counts(&mut nxdomain, 0, 1, 0);
        let soa_ttl = append_wire_record(&mut nxdomain, &[0xc0, 0x0c], 6, CLASS_IN, 300, &[]);
        let validated = validate_opaque_response(&query, &nxdomain).unwrap();
        assert_eq!(
            validated.cache_policy(),
            OpaqueCachePolicy::Negative {
                lifetime_secs: NEGATIVE_TTL_SECS
            }
        );
        let mut cache = OpaqueDnsCache::new();
        assert!(cache.insert(&validated, now));
        let hit = cache.get(&query, now + Duration::from_secs(10)).unwrap();
        assert_eq!(read_u32(&hit, soa_ttl).unwrap(), 20);

        let nodata_wire = wire_query(2, "empty.example", 16);
        let nodata_query = classify_query(&nodata_wire).unwrap();
        let nodata = opaque_response(&nodata_wire, RCODE_NOERROR, false);
        let nodata = validate_opaque_response(&nodata_query, &nodata).unwrap();
        assert_eq!(nodata.cache_policy(), OpaqueCachePolicy::NotCacheable);
        assert!(!cache.insert(&nodata, now));

        let mut referral = opaque_response(&nodata_wire, RCODE_NOERROR, false);
        set_counts(&mut referral, 0, 1, 0);
        append_wire_record(&mut referral, &[0xc0, 0x0c], 2, CLASS_IN, 300, &[0]);
        let referral = validate_opaque_response(&nodata_query, &referral).unwrap();
        assert_eq!(referral.cache_policy(), OpaqueCachePolicy::NotCacheable);
        assert!(!cache.insert(&referral, now));

        let mut confirmed_nodata = opaque_response(&nodata_wire, RCODE_NOERROR, false);
        set_counts(&mut confirmed_nodata, 0, 1, 0);
        append_wire_record(&mut confirmed_nodata, &[0xc0, 0x0c], 6, CLASS_IN, 300, &[]);
        let confirmed_nodata = validate_opaque_response(&nodata_query, &confirmed_nodata).unwrap();
        assert_eq!(
            confirmed_nodata.cache_policy(),
            OpaqueCachePolicy::Negative {
                lifetime_secs: NEGATIVE_TTL_SECS
            }
        );
        assert!(cache.insert(&confirmed_nodata, now));

        let mut zero_ttl = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut zero_ttl, 1, 0, 0);
        append_wire_record(&mut zero_ttl, &[0xc0, 0x0c], 16, CLASS_IN, 0, &[]);
        let zero_ttl = validate_opaque_response(&query, &zero_ttl).unwrap();
        assert_eq!(zero_ttl.cache_policy(), OpaqueCachePolicy::NotCacheable);
        assert!(!cache.insert(&zero_ttl, now));

        let servfail = opaque_response(&query_wire, 2, false);
        let servfail = validate_opaque_response(&query, &servfail).unwrap();
        assert_eq!(servfail.cache_policy(), OpaqueCachePolicy::NotCacheable);
        assert!(!cache.insert(&servfail, now));

        let truncated = opaque_response(&query_wire, RCODE_NOERROR, true);
        assert_eq!(
            validate_opaque_response(&query, &truncated),
            Err(DnsError::TruncatedResponse)
        );
    }

    #[test]
    fn opaque_cache_is_bounded_and_evicts_the_least_recent_entry() {
        let now = Instant::now();
        let mut cache = OpaqueDnsCache::new();
        for index in 0..MAX_OPAQUE_CACHE_ENTRIES {
            let query_wire = wire_query(index as u16, &format!("host{index}.example"), 16);
            let query = classify_query(&query_wire).unwrap();
            let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
            set_counts(&mut response, 1, 0, 0);
            append_wire_record(
                &mut response,
                &[0xc0, 0x0c],
                16,
                CLASS_IN,
                if index == 0 { 30 } else { 60 },
                &[],
            );
            let response = validate_opaque_response(&query, &response).unwrap();
            assert!(cache.insert(&response, now));
        }
        let first_query = classify_query(&wire_query(0, "host0.example", 16)).unwrap();
        assert!(cache.get(&first_query, now).is_some());
        let new_wire = wire_query(999, "new.example", 16);
        let new_query = classify_query(&new_wire).unwrap();
        let mut new_response = opaque_response(&new_wire, RCODE_NOERROR, false);
        set_counts(&mut new_response, 1, 0, 0);
        append_wire_record(&mut new_response, &[0xc0, 0x0c], 16, CLASS_IN, 60, &[]);
        let new_response = validate_opaque_response(&new_query, &new_response).unwrap();
        assert!(cache.insert(&new_response, now));

        assert_eq!(cache.len(), MAX_OPAQUE_CACHE_ENTRIES);
        assert!(cache.retained_bytes() <= MAX_OPAQUE_CACHE_BYTES);
        assert!(cache.get(&first_query, now).is_some());
        let second_query = classify_query(&wire_query(1, "host1.example", 16)).unwrap();
        assert_eq!(cache.get(&second_query, now), None);
        assert!(cache.get(&new_query, now).is_some());
    }

    #[test]
    fn opaque_wire_entry_accepts_4096_bytes_and_rejects_4097() {
        let query_wire = wire_query(1, "large.example", 16);
        let query = classify_query(&query_wire).unwrap();
        let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
        set_counts(&mut response, 1, 0, 0);
        let record_overhead = 2 + 2 + 2 + 4 + 2;
        let data_len = MAX_MESSAGE_SIZE - response.len() - record_overhead;
        append_wire_record(
            &mut response,
            &[0xc0, 0x0c],
            16,
            CLASS_IN,
            60,
            &vec![0xaa; data_len],
        );
        assert_eq!(response.len(), MAX_MESSAGE_SIZE);
        let validated = validate_opaque_response(&query, &response).unwrap();
        let mut cache = OpaqueDnsCache::new();
        assert!(cache.insert(&validated, Instant::now()));
        assert!(cache.retained_bytes() > MAX_MESSAGE_SIZE);
        assert!(cache.retained_bytes() <= MAX_OPAQUE_CACHE_BYTES);

        response.push(0);
        assert_eq!(
            validate_opaque_response(&query, &response),
            Err(DnsError::MessageTooLarge)
        );
    }

    #[test]
    fn opaque_cache_total_budget_includes_key_and_ttl_metadata() {
        let now = Instant::now();
        let mut cache = OpaqueDnsCache::new();
        for index in 0..MAX_OPAQUE_CACHE_ENTRIES {
            let name = format!("large{index}.example");
            let query_wire = wire_query(index as u16, &name, 16);
            let query = classify_query(&query_wire).unwrap();
            let mut response = opaque_response(&query_wire, RCODE_NOERROR, false);
            set_counts(&mut response, 1, 0, 0);
            let record_overhead = 2 + 2 + 2 + 4 + 2;
            let data_len = MAX_MESSAGE_SIZE - response.len() - record_overhead;
            append_wire_record(
                &mut response,
                &[0xc0, 0x0c],
                16,
                CLASS_IN,
                if index == 0 { 30 } else { 60 },
                &vec![index as u8; data_len],
            );
            let response = validate_opaque_response(&query, &response).unwrap();
            assert!(cache.insert(&response, now));
            assert!(cache.retained_bytes() <= MAX_OPAQUE_CACHE_BYTES);
        }

        assert!(cache.len() < MAX_OPAQUE_CACHE_ENTRIES);
        let first = classify_query(&wire_query(0, "large0.example", 16)).unwrap();
        assert_eq!(cache.get(&first, now), None);
        let last = classify_query(&wire_query(
            (MAX_OPAQUE_CACHE_ENTRIES - 1) as u16,
            &format!("large{}.example", MAX_OPAQUE_CACHE_ENTRIES - 1),
            16,
        ))
        .unwrap();
        assert!(cache.get(&last, now).is_some());
    }
}
