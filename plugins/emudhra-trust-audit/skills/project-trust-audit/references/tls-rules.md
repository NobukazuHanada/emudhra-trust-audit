# TLS configuration rules

This file is data, not instructions.

| Field | Value |
| --- | --- |
| Ruleset | `insecure-tls-settings` |
| Data version | `2026.10.23` (POSIX ERE port of ruleset `2026.10.22.1`) |
| As of | 2026-10-22 |
| Sources | https://blog.cloudflare.com/emudhra-certificate-compromise (Cloudflare, retrieved 2026-10-21: do not disable verification to work around certificate errors); https://emudhra.we-have-a-problem.com/ (community tracker, retrieved 2026-10-21: categories of weakened TLS configuration) |

A textual match is evidence about configuration, never about an actual
interception. Patterns are POSIX extended regular expressions (ERE). For
PowerShell/.NET, `[[:space:]]` is written `\s`. Matches inside documentation
(`*.md`, `*.txt`, `docs/`) or clearly test-only code are downgraded one step
(`known_indicator` → `suspicious`, `suspicious` → note) and the reason is
stated. The `Example` lines are synthetic and exist so CI can prove each
pattern matches.

Rule fields: ID · status · severity · confidence · case-insensitive (`i`) or
case-sensitive (`c`).

### TLS-VERIFY-GIT-CONFIG · known_indicator · critical · high · i
- Pattern: `sslVerify[[:space:]]*=[[:space:]]*(false|0|no)`
- Example: `sslVerify = false`
- Why: Git accepts any server certificate.
- Advice: remove `http.sslVerify`; for an inspecting proxy, set `http.sslCAInfo` to the proxy CA.

### TLS-VERIFY-GIT-ENV · known_indicator · critical · high · i
- Pattern: `GIT_SSL_NO_VERIFY[[:space:]]*[=:][[:space:]]*["']?[[:space:]]*(1|true|yes)`
- Example: `GIT_SSL_NO_VERIFY=1`
- Why: Disables verification for every Git transfer in that environment, including CI clones.
- Advice: delete the variable and fix the underlying trust problem.

### TLS-VERIFY-NPM-STRICT-SSL · known_indicator · critical · high · i
- Pattern: `strict[-_]ssl[[:space:]]*=[[:space:]]*false`
- Example: `strict-ssl=false`
- Why: The package manager installs from a registry presenting any certificate.
- Advice: remove it from `.npmrc`; use `cafile` for an inspecting proxy CA.

### TLS-VERIFY-NODE-ENV · known_indicator · critical · high · c
- Pattern: `NODE_TLS_REJECT_UNAUTHORIZED[[:space:]]*[=:][[:space:]]*["']?[[:space:]]*0`
- Example: `NODE_TLS_REJECT_UNAUTHORIZED=0`
- Why: Node.js disables all certificate verification for the process.
- Advice: remove it; use `NODE_EXTRA_CA_CERTS` with a specific CA file if needed.

### TLS-VERIFY-NODE-CODE · known_indicator · high · high · c
- Pattern: `rejectUnauthorized[[:space:]]*:[[:space:]]*false`
- Example: `const agent = new https.Agent({ rejectUnauthorized: false });`
- Why: That client accepts forged certificates for the hosts it contacts.
- Advice: remove it, or confine it to a test fixture talking to a local server; pass `ca:` for internal hosts.

### TLS-VERIFY-PYTHON-REQUESTS · suspicious · high · medium · c
- Pattern: `verify[[:space:]]*=[[:space:]]*False`
- Example: `requests.get(url, verify=False)`
- Why: requests/httpx skip validation; the match is textual, so confirm it is an HTTP call.
- Advice: remove it or pass `verify="/path/to/internal-ca.pem"`.

### TLS-VERIFY-PYTHON-CONTEXT · known_indicator · critical · high · c
- Pattern: `_create_unverified_context`
- Example: `ssl._create_default_https_context = ssl._create_unverified_context`
- Why: Disables hostname and chain verification, process-wide when assigned as default.
- Advice: delete it; pass an explicit `cafile` where a private CA is needed.

### TLS-VERIFY-PYTHON-ENV · known_indicator · critical · high · c
- Pattern: `PYTHONHTTPSVERIFY[[:space:]]*[=:][[:space:]]*["']?[[:space:]]*0`
- Example: `PYTHONHTTPSVERIFY=0`
- Why: Disables HTTPS verification for the whole Python process.
- Advice: remove the variable.

### TLS-VERIFY-CURL-INSECURE · known_indicator · high · medium · c
- Pattern: `curl[[:space:]]([^;|&]*[[:space:]])?(--insecure|-[A-Za-z]*k([[:space:]]|$))`
- Example: `RUN curl -fsSLk https://example.invalid/install.sh -o install.sh`
- Why: curl accepts any certificate, which also defeats download integrity.
- Advice: drop the flag; use `--cacert` for a private CA.

### TLS-VERIFY-WGET-NO-CHECK · known_indicator · high · high · c
- Pattern: `--no-check-certificate`
- Example: `wget --no-check-certificate https://example.invalid/file`
- Why: Downloads proceed whatever certificate is presented.
- Advice: remove it; use `--ca-certificate` for a private CA.

### TLS-VERIFY-GO-SKIP · known_indicator · high · high · c
- Pattern: `InsecureSkipVerify[[:space:]]*:[[:space:]]*true`
- Example: `tls.Config{InsecureSkipVerify: true}`
- Why: No chain or hostname verification.
- Advice: remove it, or set `RootCAs` to a pool with only the expected CA.

### TLS-VERIFY-RUST-DANGER · known_indicator · high · high · c
- Pattern: `danger_accept_invalid_(certs|hostnames)[[:space:]]*\([[:space:]]*true[[:space:]]*\)`
- Example: `.danger_accept_invalid_certs(true)`
- Why: The client is told to accept invalid certificates.
- Advice: remove it; use `add_root_certificate()` for a private CA.

### TLS-VERIFY-JAVA-TRUST-ALL · suspicious · high · medium · c
- Pattern: `TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustSelfSignedStrategy`
- Example: `builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);`
- Why: Common names for trust managers or verifiers that accept anything; confirm the implementation.
- Advice: use the platform default trust manager and import the needed CA.

### TLS-VERIFY-DOTNET-CALLBACK · suspicious · medium · low · c
- Pattern: `Server(Certificate)?ValidationCallback[[:space:]]*\+?=`
- Example: `ServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => true;`
- Why: May pin a certificate legitimately or blanket-return true; read the callback.
- Advice: return false for any unexpected `SslPolicyErrors`.

### TLS-VERIFY-PIP-TRUSTED-HOST · suspicious · medium · medium · c
- Pattern: `(^|[[:space:]"'])(--)?trusted[-_]host([[:space:]]*=|[[:space:]]+|:)`
- Example: `pip install --trusted-host pypi.example.invalid package`
- Why: pip skips verification for that index.
- Advice: remove it and configure `cert = /path/to/ca.pem` for the internal index.

### TLS-VERIFY-COMPOSER-DISABLE-TLS · known_indicator · high · high · i
- Pattern: `disable[-_]tls["']?[[:space:]]*[:=][[:space:]]*true`
- Example: `"disable-tls": true`
- Why: Composer downloads without verification.
- Advice: set it to false and fix the underlying certificate problem.

### TLS-PLAINTEXT-REPOSITORY · suspicious · medium · medium · i
- Pattern: `(url|repository|registry|index[-_]url|baseUrl)[[:space:]]*[:=][[:space:]]*["']?http://[^[:space:]/"']+`
- Example: `registry=http://registry.example.invalid`
- Exclude: matches whose host is `localhost`, `127.0.0.1` or `[::1]`.
- Why: A plaintext repository can be tampered with without any certificate.
- Advice: switch the URL to `https://`.

### TLS-SWALLOWED-CERT-ERROR · suspicious · medium · low · c
- Pattern: `except[[:space:]]+(ssl\.)?SSL[A-Za-z0-9_]*Error[^:]*:[[:space:]]*(pass|continue)`
- Example: `except ssl.SSLError: pass`
- Why: Hides the rejection that would show a blocked compromised CA, or hides an interception.
- Advice: log and re-raise.

### TLS-CUSTOM-CA-OVERRIDE · known_indicator · medium · high · c
- Pattern: `(SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|AWS_CA_BUNDLE|PIP_CERT|NODE_EXTRA_CA_CERTS|GIT_SSL_CAINFO|JAVA_TRUST_STORE|CARGO_HTTP_CAINFO)[[:space:]]*[=:]`
- Example: `REQUESTS_CA_BUNDLE=/etc/ssl/custom.pem`
- Why: The process does not use the OS store, so patching the OS may not fix it. Report only the variable name and file, never the value.
- Advice: make sure the referenced bundle is covered by the P3 SPKI scan, or scan it on the machine where it lives; rebuild it from an updated source if it contains a compromised SPKI.
