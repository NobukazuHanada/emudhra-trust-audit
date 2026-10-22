# Synthetic certificate fixtures

The PEM files in `certs/` were generated for this project, not downloaded from
an advisory. Names containing "Fixture" are artificial. No fixture is a real
compromised eMudhra certificate and no private key is distributed.

Tests copy production indicator data into a temporary directory and substitute
the synthetic certificate's SPKI, then regenerate checksums. This exercises DER
parsing and matching without redistributing third-party certificate material.
`not-a-cert.pem` deliberately contains invalid data. Fixtures are Apache-2.0
alongside the project. Do not install them into any trust store.
