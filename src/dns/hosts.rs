use super::policy::DomainIndex;
use crate::config::{HostEntry, HostValue, MAX_CONFIG_BYTES};
use std::{
    collections::HashSet,
    io::{self, Read},
    net::IpAddr,
};

pub(crate) struct Hosts {
    index: DomainIndex,
    system: std::collections::HashMap<String, HostValue>,
    values: Vec<HostValue>,
}

impl Hosts {
    pub(crate) fn new(entries: &[HostEntry], configured: bool, system: bool) -> Self {
        let mut hosts = Self {
            index: DomainIndex::new(),
            system: std::collections::HashMap::new(),
            values: Vec::new(),
        };
        if system {
            #[cfg(windows)]
            let path = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| "C:\\Windows".into())
                .join("System32/drivers/etc/hosts");
            #[cfg(not(windows))]
            let path = std::path::PathBuf::from("/etc/hosts");
            if let Ok(file) = std::fs::File::open(path) {
                let mut text = String::new();
                if file
                    .take(MAX_CONFIG_BYTES as u64)
                    .read_to_string(&mut text)
                    .is_ok()
                {
                    let mut entries = std::collections::BTreeMap::<String, Vec<IpAddr>>::new();
                    for line in text.lines() {
                        let mut words = line.split('#').next().unwrap_or("").split_whitespace();
                        let Some(ip) = words.next().and_then(|word| word.parse::<IpAddr>().ok())
                        else {
                            continue;
                        };
                        for name in words {
                            if let Ok(name) = super::canonicalize_name(name) {
                                entries.entry(name).or_default().push(ip);
                            }
                        }
                    }
                    for (name, addresses) in entries {
                        hosts.system.insert(name, HostValue::Addresses(addresses));
                    }
                }
            }
        }
        if configured {
            for entry in entries {
                hosts.insert(&entry.pattern, entry.value.clone());
            }
        }
        hosts
    }
    fn insert(&mut self, name: &str, value: HostValue) {
        self.index.insert(name, self.values.len());
        self.values.push(value);
    }
    pub(crate) fn lookup(&self, name: &str) -> io::Result<HostValue> {
        let mut name = name.to_owned();
        let mut seen = HashSet::new();
        while let Some(value) = self
            .index
            .find(0, &name)
            .map(|index| &self.values[index])
            .or_else(|| self.system.get(&name))
        {
            if !seen.insert(name.clone()) || seen.len() > 32 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            match value {
                HostValue::Addresses(addresses) => {
                    return Ok(HostValue::Addresses(addresses.clone()));
                }
                HostValue::Alias(alias) => name.clone_from(alias),
            }
        }
        Ok(HostValue::Alias(name))
    }
}

pub(crate) fn validate(entries: &[HostEntry]) -> io::Result<()> {
    let hosts = Hosts::new(entries, true, false);
    for entry in entries {
        hosts.lookup(&entry.pattern)?;
    }
    Ok(())
}
