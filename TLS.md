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
- Existing `display` destinations retain their existing plaintext behavior.
  A TLS failure **never** falls back to those destinations automatically; if
  plaintext and TLS entries coexist, each is an independently configured target.

The prototype uses Schannel TLS1.2, requiring a Windows version/patch level with
TLS1.2 and exclusive-root chain-engine support. It validates server chain,
validity, serverAuth usage and hostname before sending application data. The
client certificate is supplied explicitly; automatic anonymous retry is disabled.
No custom encryption, OpenSSL DLLs, passwords or private-key files are involved.

Socket connect, handshake and all report writes share a ten-second deadline per
TLS destination. TLS destinations currently execute sequentially, before the
legacy plaintext sending phase. Each report gets a fresh connection/credentials;
partial writes and TLS record sizing are handled, followed by close_notify.
No durable spool or delivery acknowledgment is added: a successful write is not
proof that the Xymon server processed the report.

## Tests and builds

`make -j4 all` cross-compiles the complete x86/x64 clients with MinGW-w64.
No new runtime library dependency is added beyond Windows libraries already
linked by the main client (`secur32`, `crypt32`, `ws2_32`).

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
identity and a stalled handshake deadline. Tests are skipped outside Windows;
that does **not** constitute passing Schannel runtime validation.

## Before production acceptance

- Obtain passing Windows integration results for both architectures and review
  packet fragmentation, credential renewal/reload, inaccessible/non-exportable
  CNG keys, expired/rejected client certificates and peer disconnects.
- Define and implement an explicit revocation policy. The current prototype
  uses cache-only chain building **without requesting revocation checking**;
  do not describe it as revocation-validated or production-ready.
- Improve failure diagnostics (stage/status codes, never payloads or keys).
- Review service-stop responsiveness and aggregate delays with many TLS targets.
- Resolve TLS1.3 support and the supported Windows baseline before release.
- Review build provenance, license/distribution requirements and code signing.
- Pilot separately after development review; no live installation is authorized
  by this feature branch alone.
