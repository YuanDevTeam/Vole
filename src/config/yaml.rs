use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_yaml_ng::{Mapping, Value};

use crate::{Result, VoleError};

use super::MAX_CONFIG_BYTES;

/// Charge aliases while they are expanded, before allocating their values.
/// An input-size limit alone does not bound the materialized YAML tree.
pub(super) fn parse(input: &[u8]) -> Result<Value> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(VoleError::InvalidConfig(format!(
            "configuration exceeds the {MAX_CONFIG_BYTES}-byte limit"
        )));
    }
    let mut documents = serde_yaml_ng::Deserializer::from_slice(input);
    let document = documents.next().ok_or_else(|| {
        VoleError::InvalidConfig("configuration must contain one YAML document".into())
    })?;
    let mut budget = MAX_CONFIG_BYTES * 4;
    let mut value = BoundedValue {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(document)
    .map_err(|error| VoleError::InvalidConfig(error.to_string()))?;
    if documents.next().is_some() {
        return Err(VoleError::InvalidConfig(
            "configuration must contain one YAML document".into(),
        ));
    }
    merge(&mut value)?;
    Ok(value)
}

struct BoundedValue<'a> {
    budget: &'a mut usize,
    depth: usize,
}

impl BoundedValue<'_> {
    fn charge<E: de::Error>(&mut self, bytes: usize) -> std::result::Result<(), E> {
        *self.budget = self
            .budget
            .checked_sub(bytes)
            .ok_or_else(|| E::custom("expanded YAML exceeds the configuration memory limit"))?;
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(
        mut self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.depth > 64 {
            return Err(de::Error::custom("YAML nesting exceeds 64 levels"));
        }
        self.charge::<D::Error>(64)?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("YAML data without custom tags")
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_str<E: de::Error>(mut self, value: &str) -> std::result::Result<Value, E> {
        self.charge::<E>(value.len())?;
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(mut self, value: String) -> std::result::Result<Value, E> {
        self.charge::<E>(value.len())?;
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedValue {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Sequence(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Mapping::new();
        while let Some(key) = map.next_key_seed(BoundedValue {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if !matches!(key, Value::String(_)) {
                return Err(de::Error::custom("YAML map keys must be strings"));
            }
            let value = map.next_value_seed(BoundedValue {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate YAML map key"));
            }
        }
        Ok(Value::Mapping(values))
    }
}

fn merge(value: &mut Value) -> Result<()> {
    match value {
        Value::Sequence(values) => {
            for value in values {
                merge(value)?;
            }
        }
        Value::Mapping(mapping) => {
            for value in mapping.values_mut() {
                merge(value)?;
            }
            if let Some(source) = mapping.remove("<<") {
                let sources = match source {
                    Value::Sequence(values) => values,
                    source => vec![source],
                };
                for source in sources {
                    let Value::Mapping(source) = source else {
                        return Err(VoleError::InvalidConfig("YAML merge requires maps".into()));
                    };
                    for (key, value) in source {
                        mapping.entry(key).or_insert(value);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}
