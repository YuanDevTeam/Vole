//! kcptun's 6-byte FEC envelope and systematic GF(256) Reed-Solomon shards.
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{collections::BTreeMap, io};
const DATA: u16 = 0xf1;
const PARITY: u16 = 0xf2;
const GROUPS: usize = 4;
pub(super) struct Fec {
    codec: Option<ReedSolomon>,
    k: usize,
    n: usize,
    next: u32,
    limit: u32,
    outgoing: Vec<Vec<u8>>,
    incoming: BTreeMap<u32, Group>,
}
struct Group {
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
}
impl Fec {
    pub(super) fn new(k: u8, n: u8) -> io::Result<Self> {
        let (k, n) = (usize::from(k), usize::from(n));
        let codec = if k == 0 || n == 0 {
            None
        } else {
            Some(ReedSolomon::new(k, n).map_err(codec_error)?)
        };
        let size = (k + n).max(1) as u32;
        Ok(Self {
            codec,
            k,
            n,
            next: 0,
            limit: u32::MAX / size * size,
            outgoing: Vec::new(),
            incoming: BTreeMap::new(),
        })
    }
    pub(super) fn overhead(&self) -> usize {
        if self.codec.is_some() { 8 } else { 0 }
    }
    pub(super) fn encode(&mut self, packet: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        if self.codec.is_none() {
            return Ok(vec![packet.to_vec()]);
        }
        let mut shard = Vec::with_capacity(packet.len() + 2);
        shard.extend_from_slice(&((packet.len() + 2) as u16).to_le_bytes());
        shard.extend_from_slice(packet);
        let mut output = vec![self.frame(DATA, &shard)];
        self.outgoing.push(shard);
        if self.outgoing.len() == self.k {
            let length = self.outgoing.iter().map(Vec::len).max().unwrap();
            let mut shards = std::mem::take(&mut self.outgoing);
            for shard in &mut shards {
                shard.resize(length, 0);
            }
            shards.extend((0..self.n).map(|_| vec![0; length]));
            self.codec
                .as_ref()
                .unwrap()
                .encode(&mut shards)
                .map_err(codec_error)?;
            for shard in &shards[self.k..] {
                output.push(self.frame(PARITY, shard));
            }
        }
        Ok(output)
    }
    fn frame(&mut self, kind: u16, shard: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(shard.len() + 6);
        result.extend_from_slice(&self.next.to_le_bytes());
        result.extend_from_slice(&kind.to_le_bytes());
        result.extend_from_slice(shard);
        self.next = (self.next + 1) % self.limit;
        result
    }
    pub(super) fn decode(&mut self, wire: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        if wire.len() < 6 {
            return Ok(Vec::new());
        }
        let kind = u16::from_le_bytes(wire[4..6].try_into().unwrap());
        if !matches!(kind, DATA | PARITY) {
            return Ok(vec![wire.to_vec()]);
        }
        if self.codec.is_none() || wire.len() < 8 {
            return Ok(Vec::new());
        }
        let sequence = u32::from_le_bytes(wire[..4].try_into().unwrap());
        let size = (self.k + self.n) as u32;
        let group = sequence / size;
        let index = (sequence % size) as usize;
        if (kind == DATA) != (index < self.k) {
            return Ok(Vec::new());
        }
        if !self.incoming.contains_key(&group) && self.incoming.len() == GROUPS {
            self.incoming.pop_first();
        }
        let entry = self.incoming.entry(group).or_insert_with(|| Group {
            shards: vec![None; self.k + self.n],
            delivered: vec![false; self.k],
        });
        let mut output = Vec::new();
        if kind == DATA && !entry.delivered[index] {
            let length = usize::from(u16::from_le_bytes(wire[6..8].try_into().unwrap()));
            if !(2..=wire.len() - 6).contains(&length) {
                return Ok(Vec::new());
            }
            entry.delivered[index] = true;
            output.push(wire[8..6 + length].to_vec());
        }
        if entry.shards[index].is_some() {
            return Ok(output);
        }
        entry.shards[index] = Some(wire[6..].to_vec());
        if entry.shards.iter().flatten().count() >= self.k {
            let length = entry.shards.iter().flatten().map(Vec::len).max().unwrap();
            for shard in entry.shards.iter_mut().flatten() {
                shard.resize(length, 0);
            }
            if self
                .codec
                .as_ref()
                .unwrap()
                .reconstruct_data(&mut entry.shards)
                .is_ok()
            {
                for index in 0..self.k {
                    if entry.delivered[index] {
                        continue;
                    }
                    if let Some(shard) = &entry.shards[index] {
                        let n = usize::from(u16::from_le_bytes(shard[..2].try_into().unwrap()));
                        if (2..=shard.len()).contains(&n) {
                            output.push(shard[2..n].to_vec());
                        }
                    }
                }
            }
            self.incoming.remove(&group);
        }
        Ok(output)
    }
}

fn codec_error(error: reed_solomon_erasure::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn systematic_shards_recover_loss_reordering_and_have_bounded_groups() {
        let mut encoder = Fec::new(3, 2).unwrap();
        let mut packets = Vec::new();
        for data in [b"first".as_slice(), b"second", b"third"] {
            packets.extend(encoder.encode(data).unwrap());
        }
        assert_eq!(packets.len(), 5);
        assert_eq!(&packets[0][..8], &[0, 0, 0, 0, 0xf1, 0, 7, 0]);
        let mut decoder = Fec::new(3, 2).unwrap();
        let mut recovered = Vec::new();
        for i in [4, 2, 0] {
            recovered.extend(decoder.decode(&packets[i]).unwrap());
        }
        recovered.sort();
        assert_eq!(
            recovered,
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        for sequence in (50u32..100).step_by(5) {
            let mut packet = packets[0].clone();
            packet[..4].copy_from_slice(&sequence.to_le_bytes());
            decoder.decode(&packet).unwrap();
            assert!(decoder.incoming.len() <= GROUPS);
        }
        let mut plain = Fec::new(0, 0).unwrap();
        assert_eq!(plain.encode(b"raw").unwrap(), [b"raw".to_vec()]);
    }
}
