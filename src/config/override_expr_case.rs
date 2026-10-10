//! Independent single-scalar mapping over the attributed Unicode 15 data.
use std::cmp::Ordering;

#[path = "../../vendor/go-unicode-case-ranges/case_ranges.rs"]
mod data;

pub(super) fn map(character: char, upper: bool) -> char {
    let scalar = u32::from(character);
    let Ok(index) = data::CASE_RANGES.binary_search_by(|&(first, last, _, _)| {
        if scalar < first {
            Ordering::Greater
        } else if scalar > last {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }) else {
        return character;
    };
    let (first, _, uppercase, lowercase) = data::CASE_RANGES[index];
    let delta = if upper { uppercase } else { lowercase };
    let mapped = if delta == 0x110000 {
        first + ((scalar - first) / 2) * 2 + u32::from(!upper)
    } else if delta < 0 {
        scalar - delta.unsigned_abs()
    } else {
        scalar + delta as u32
    };
    char::from_u32(mapped).unwrap_or(character)
}
