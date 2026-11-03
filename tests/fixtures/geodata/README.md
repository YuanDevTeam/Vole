# GeoData fixtures

`GeoLite2-ASN-Test.mmdb` is the small official MaxMind test database from
[MaxMind-DB](https://github.com/maxmind/MaxMind-DB/tree/6a690a705bc6962c0025a32e94a8f0dc8f86418c),
commit `6a690a705bc6962c0025a32e94a8f0dc8f86418c`, path
`test-data/GeoLite2-ASN-Test.mmdb`.

Copyright © 2013–2026 MaxMind, Inc. Used under the upstream MIT option; the
permission notice is preserved in [LICENSE-MIT](LICENSE-MIT). This source fixture
is not part of Vole runtime or release packages.

`Country-Test.mmdb`, `Sing-Test.mmdb`, and `Meta-Test.mmdb` are independently
encoded Vole fixtures using the [MaxMind DB 2.0 format](https://maxmind.github.io/MaxMind-DB/).
One 24-bit node maps the lower IPv6 half (including IPv4 lookups) to CN and the
upper half to US. Records respectively use `country.iso_code`, a root string,
and a root array (`cn`, `private`) or string (`us`). They contain synthetic
data and no third-party database records.
