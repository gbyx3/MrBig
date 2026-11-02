# Native Windows TLS — experimental

Development branch: `feature/schannel-tls`, based on Axians `develop` v0.26.7.
This is an initial implementation, **not a signed release or production approval**.

## Configuration

Use a TLS destination instead of a plaintext `display` entry:

```ini
[mrbig]
machine server.example.org
tls_display 192.0.2.10:1985 proxy.example.org
tls_client_thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
tls_ca_file C:\ProgramData\MrBig\transport-root.pem
tls_crl_file C:\ProgramData\MrBig\transport-issuer.crl
```

- `tls_display` requires numeric IPv4, explicit port and DNS verification name.
  The name is also used for SNI. Multiple destinations are supported.
- `tls_client_thumbprint` selects a certificate from **LocalMachine\My**.
  Use its 40 hexadecimal SHA-1 thumbprint without spaces (a store identifier,
  not a SHA-1 signature or a server trust bypass). The service identity must
  have permission to use the associated private key. Keys are never exported.
- `tls_ca_file` is an optional single PEM/DER root certificate, used by an
  exclusive, connection-local chain engine. It does not install global trust.
  Without it, validation uses the LocalMachine Windows trust configuration.
  Paths with spaces are accepted without quoting. Restrict write access to
  configuration and CA files to administrators.
- Configuration applies to every TLS destination regardless of directive order.
- `tls_crl_file` supplies a signed PEM/DER CRL to the connection-local validation
  store. Revocation validation is mandatory for every non-root server certificate;
  absent, stale, incorrectly signed or revoking evidence fails closed. With no
  local CRL, fresh Windows cached revocation evidence is required. There is no
  ignore/off switch and no online retrieval by this transport. Plan protected,
  atomic CRL refreshes and alert before nextUpdate; issuer chains may require
  additional fresh evidence in the Windows cache. The root is excluded from
  revocation checking; removing that configured trust anchor is the recovery
  mechanism for a compromised root.
- Existing `display` destinations retain their existing plaintext behavior.
  A TLS failure **never** falls back to those destinations automatically; if
  plaintext and TLS entries coexist, each is an independently configured target.

The prototype uses modern Schannel credentials (Windows10/Server2019 or newer),
negotiating TLS1.2 or TLS1.3 where the OS enables it. SSL2/3 and TLS1.0/1.1 are
disabled. TLS1.3 requires Windows11/Server2022 or newer. It validates server chain,
validity, serverAuth usage and hostname before sending application data. The
client certificate is supplied explicitly; automatic anonymous retry is disabled.
No custom encryption, OpenSSL DLLs, passwords or private-key files are involved.

Main-client builds enable strong stack protection (including clientlog objects),
ASLR and NX, with high-entropy ASLR on x64. Stack-protector/GCC support is linked
statically to avoid introducing third-party runtime DLL deployment. PE linker
timestamps are zeroed. `tests/check_pe_hardening.py` checks both executables;
this is not yet a claim of byte-for-byte reproducible builds or Control Flow Guard.
Native import checks are not a complete dependency vulnerability scan.

Socket connect, handshake and all report writes share a ten-second budget across
TLS destinations in each send_update call. Destinations currently execute
sequentially; the existing plaintext phase is unchanged. Service-stop signaling
cancels TLS socket waits, checked at most100ms apart. This does not redesign or
prove prompt stopping of the legacy collectors/service as a whole.
Each report gets a fresh connection/credentials;
partial writes and TLS record sizing are handled, followed by close_notify.
No durable spool or delivery acknowledgment is added: a successful write is not
proof that the Xymon server processed the report.

## Tests and builds

`make -j4 all` cross-compiles the complete x86/x64 clients with MinGW-w64.
No new runtime library dependency is added beyond Windows libraries already
linked by the main client (`secur32`, `crypt32`, `ws2_32`) except Windows' native
`ncrypt` library for machine-key acquisition/release. There is no new third-party
runtime DLL dependency.

Portable parser tests (macOS/Linux):

```sh
cc -Wall -Wextra -Werror -fsanitize=address,undefined -I. \
  tests/test_tls_endpoint.c tls_endpoint.c -o /tmp/test-tls-endpoint
/tmp/test-tls-endpoint
```

`.github/workflows/schannel-tests.yml` builds both clients/probes and runs Windows
integration tests on disposable GitHub-hosted Windows runners. The tests create
one local machine-store test identity and delete it and its key afterwards; they
never install a system root or touch production infrastructure. Do not run them
on production identity servers. Test coverage includes a 64KiB report, clean TLS
shutdown, wrong hostname/root/EKU, expired server certificate, missing client
identity and a stalled handshake deadline. Hardening adds revocation evidence
failures, non-exportable native CNG machine keys, renewed identities, fragmented
handshakes, TLS1.3, rejected clients, peer disconnects and service cancellation.
All 18 expanded tests passed on both architectures for revision `2438e65`:
https://github.com/gbyx3/MrBig/actions/runs/41452474814.
The subsequent build-hardening changes still require their own CI acceptance.
Tests are skipped outside Windows;
that does **not** constitute passing Schannel runtime validation.

## Before production acceptance

- Obtain passing Windows integration results for both architectures and review
  packet fragmentation, credential renewal/reload, inaccessible/non-exportable
  CNG keys, expired/rejected client certificates and peer disconnects.
- Commission an actual issuer revocation/publication/refresh process before
  using the mandatory revocation policy on live monitoring infrastructure.
  No production CA or server has been changed by this development work.
- Complete native CNG key ACL-denial, same-process renewal, resource-leak,
  aggregate-delay and full service-lifecycle acceptance tests.
- Validate configuration/trust-file ownership, parent-directory protections and
  administrator-only writes in deployment; the client does not yet enforce ACLs.
  Unknown, empty or truncated TLS configuration now disables TLS rather than
  silently changing trust or downgrading. Diagnostics identify destination,
  failure stage and numeric Windows status; service environment dumps removed.
- Review build provenance, license/distribution requirements and code signing.
- New TLS CI action references, Python version and direct test-package version
  are pinned. Compiler/transitive dependency reproducibility and automated
  vulnerability scanning still require a release policy.
- Pilot separately after development review; no live installation is authorized
  by this feature branch alone.
