# TLS development security notes

This personal development fork is not an Axians release. Successful CI is not
independent security review, release signing, or permission to deploy on a DC/CA.

## Trust and threat model

- A TLS destination must verify the server name, chain, validity, usage and
  fresh revocation evidence before any report bytes are sent. Failure never
  downgrades that destination to plaintext. Explicit legacy `display` entries
  still send plaintext independently; remove them when migrating a target.
- Client authentication uses an explicitly selected LocalMachine certificate.
  A non-exportable CNG key still requires a restrictive **key-use ACL**: lack of
  export permission alone does not stop another privileged process using it.
- Mutual TLS authenticates the connection, not every hostname in its Xymon
  payload. Authorization binding a certificate to permitted report identities
  remains a receiver/proxy concern. A compromised enrolled host must not be
  considered harmless just because its certificate is valid.
- The process does not download AIA, CRL or OCSP URLs embedded in certificates.
  Administrators must supply/refresh signed local CRLs or provision fresh Windows
  cached evidence. Every non-root server-chain certificate must be covered.
  Missing/stale evidence is an outage, not permission to disable revocation.
- Root compromise is handled by explicit trust-anchor removal/replacement.
  Issuer CRLs cannot revoke their own root trust anchor. Issuance, publication,
  rotation and emergency revocation are operational responsibilities outside
  the client development task.

## Deployment gates

Use a reviewed installation directory, preferably under Program Files, and
place configuration/root/CRL files in a protected ProgramData directory.

1. Inspect existing ownership/ACLs and preserve a protected recovery copy.
2. Ensure files **and parent directories** cannot be written, replaced, renamed
   or have ownership/DACLs changed by ordinary users. Allow administrators and
   SYSTEM to manage files; grant the selected service identity only needed read
   and machine-key-use permissions. Keep logs in a separate writable directory.
3. Do not use network shares, reparse-point redirections, relative paths or
   alternate data streams for trust inputs. The parser rejects non-local drive
   paths, ADS syntax and ambiguous path components, but runtime ACL/reparse-point
   enforcement is not yet implemented. A local drive can itself be redirected:
   parser validation alone is not evidence that storage is trustworthy/local.
4. Refresh CRLs atomically before nextUpdate, validate signatures/freshness, and
   keep signed recovery evidence. Do not automatically replace trust roots.
5. Install only reviewed, provenance-checked, appropriately Authenticode-signed
   builds. This branch currently creates **unsigned development binaries**.
6. Test the supported OS baseline and service identity/key ACLs on an isolated
   Windows host before any production pilot. A whole-service stop/restart and
   multi-destination regression suite remains required.

No installer/ACL script in this repository has been run against production.
Do not weaken global Schannel/Windows certificate validation or grant broad
machine-key access to make a TLS test pass.

## Diagnostics

New TLS failure messages contain only destination, failure stage and numeric
Windows status. They must not include report bodies, passwords, private keys,
environment dumps, memory dumps or full raw configuration. Existing legacy debug
and crash facilities require separate review and protected retention; do not
turn them on globally during a production investigation.

## Remaining review

Before a release, obtain review by someone other than the implementation author,
review dependency/build provenance and signing, test resource use under repeated
failure/success, key-ACL denial and renewal, and verify unchanged behavior of
legacy destinations. Do not publish a security finding with keys or sensitive
infrastructure evidence; coordinate privately with the relevant maintainers.
