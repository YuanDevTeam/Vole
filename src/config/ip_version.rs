use super::*;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum IpVersion {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
    Ipv4Prefer,
    Ipv6Prefer,
}
impl TryFrom<String> for IpVersion {
    type Error = &'static str;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "dual" => Ok(Self::Dual),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "ipv4-prefer" => Ok(Self::Ipv4Prefer),
            "ipv6-prefer" => Ok(Self::Ipv6Prefer),
            _ => Err("invalid ip-version"),
        }
    }
}
impl IpVersion {
    pub fn permits(self, address: IpAddr) -> bool {
        match self {
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
            _ => true,
        }
    }
    pub(crate) fn order(self, addresses: &mut Vec<SocketAddr>) {
        addresses.retain(|address| self.permits(address.ip()));
        match self {
            Self::Ipv4Prefer => addresses.sort_by_key(|address| address.is_ipv6()),
            Self::Ipv6Prefer => addresses.sort_by_key(|address| address.is_ipv4()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_policy_orders_and_filters_physical_candidates() {
        let addresses: Vec<SocketAddr> =
            ["[2001:db8::1]:443", "192.0.2.1:443", "[2001:db8::2]:443"]
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect();
        let preferred = crate::dialer::Dialer::default()
            .with_ip_version(IpVersion::Ipv4Prefer)
            .ordered_addresses(&addresses);
        assert_eq!(preferred, vec![addresses[1], addresses[0], addresses[2]]);
        assert_eq!(
            crate::dialer::Dialer::default()
                .with_ip_version(IpVersion::Ipv4)
                .ordered_addresses(&addresses),
            vec![addresses[1]]
        );
        assert!(
            crate::dialer::Dialer::default()
                .with_ipv6(false)
                .with_ip_version(IpVersion::Ipv6)
                .ordered_addresses(&addresses)
                .is_empty()
        );
    }
}
