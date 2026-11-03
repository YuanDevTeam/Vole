# AGE provider fixtures

Synthetic X25519 and ML-KEM-768/X25519 Hybrid recipients were generated with
the public `filippo.io/age` v1.3.2 API (`GenerateX25519Identity`,
`GenerateHybridIdentity`, `Encrypt`, and `armor.NewWriter`). Both decrypt to
`provider.yaml`. The public fixture keys are only for tests.

These fixtures check compatibility against an independent implementation; no
reference-client source or tests were copied.
