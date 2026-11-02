"""Disposable Windows runner only: creates/removes one machine-store test identity.

Run: python -m unittest discover -s tests -p test_tls_windows.py -v
Requires cryptography and MRBIG_TLS_PROBE pointing to the compiled test harness.
No live infrastructure, administrator keys, or system-root trust changes.
"""
import datetime
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

if sys.platform == "win32":
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@unittest.skipUnless(sys.platform == "win32", "Schannel requires Windows")
class SchannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.probe = os.environ["MRBIG_TLS_PROBE"]
        cls.thumbprints = []
        now = datetime.datetime.now(datetime.timezone.utc)

        def issue(name, issuer=None, issuer_key=None, ca=False, expired=False, client=False):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            builder = (x509.CertificateBuilder().subject_name(subject)
                       .issuer_name(issuer.subject if issuer else subject)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - datetime.timedelta(days=2))
                       .not_valid_after(now + datetime.timedelta(days=-1 if expired else 2))
                       .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                       .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                           key_encipherment=True, data_encipherment=False, key_agreement=False,
                           key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
            if not ca:
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            cert = builder.sign(issuer_key or key, hashes.SHA256())
            (cls.root / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (cls.root / (name + ".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            return cert, key

        ca, ca_key = issue("test-root", ca=True)
        issue("other-root", ca=True)
        server, _ = issue("proxy.example", ca, ca_key)
        issue("fresh.example", ca, ca_key)
        issue("revoked.example", ca, ca_key)
        issue("expired.example", ca, ca_key, expired=True)
        issue("wrong-eku.example", ca, ca_key, client=True)
        client, key = issue("client.example", ca, ca_key, client=True)
        cls.thumbprint = client.fingerprint(hashes.SHA1()).hex().upper()
        cls.thumbprints.append(cls.thumbprint)
        cls.ca, cls.ca_key = ca, ca_key
        # Each fixture has fresh local evidence. Missing/expired/revoked CRLs must fail.
        for name, expired, revoked, signer in [
                ("valid", False, False, ca_key), ("expired", True, False, ca_key),
                ("revoked", False, True, ca_key),
                ("bad-signature", False, False, rsa.generate_private_key(public_exponent=65537, key_size=2048))]:
            crl = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
                   .last_update(now - datetime.timedelta(days=2))
                   .next_update(now + datetime.timedelta(days=-1 if expired else 2)))
            if revoked:
                entry = (x509.RevokedCertificateBuilder().serial_number(server.serial_number)
                         .revocation_date(now - datetime.timedelta(days=1)).build())
                crl = crl.add_revoked_certificate(entry)
            (cls.root / (name + ".crl")).write_bytes(crl.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        pfx = cls.root / "client.pfx"
        pfx.write_bytes(pkcs12.serialize_key_and_certificates(b"MrBig disposable test", key,
            client, None, serialization.NoEncryption()))
        # Use the certificate-store API directly, not a profile-dependent Cert: drive.
        # The PFX contains only this leaf and key, never the test CA.
        cls.addClassCleanup(cls.temp.cleanup)
        cls.addClassCleanup(cls.remove_identity)
        subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$flags=[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet "
            "-bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet;"
            "$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new('" +
            str(pfx).replace("'", "''") + "',[string]::Empty,$flags);"
            "$store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');"
            "try {$store.Open('ReadWrite');$store.Add($cert)}"
            "finally {$store.Dispose();$cert.Dispose()}"], check=True)

        cls.cng_thumbprint = cls.create_cng_identity("native-client")
        cls.renewed_thumbprint = cls.create_cng_identity("renewed-client")

    @classmethod
    def create_cng_identity(cls, name):
        """Generate a persisted, non-exportable machine key; export only its CSR."""
        key_name = "MrBig-test-" + os.urandom(12).hex()
        cls.addClassCleanup(cls.remove_cng_key, key_name)
        result = subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$p=[Security.Cryptography.CngKeyCreationParameters]::new();"
            "$p.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;"
            "$p.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey;"
            "$p.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None;"
            "$key=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,'" + key_name + "',$p);"
            "$rsa=[Security.Cryptography.RSACng]::new($key);"
            "try{$request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=" + name + "',$rsa,"
            "[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);"
            "$blocked=$false;try{$null=$rsa.ExportPkcs8PrivateKey()}catch{$blocked=$true};"
            "@{csr=[Convert]::ToBase64String($request.CreateSigningRequest());"
            "nonexportable=$blocked;machine=$key.IsMachineKey}|ConvertTo-Json -Compress}"
            "finally{$rsa.Dispose();$key.Dispose()}"], check=True, capture_output=True, text=True)
        metadata = json.loads(result.stdout)
        if not metadata["nonexportable"] or not metadata["machine"]:
            raise AssertionError("Expected a non-exportable CNG machine key")
        import base64
        csr = x509.load_der_x509_csr(base64.b64decode(metadata["csr"]))
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(cls.ca.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .sign(cls.ca_key, hashes.SHA256()))
        path = cls.root / (name + ".cer")
        path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
        cls.thumbprints.append(thumbprint)
        subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$key=[Security.Cryptography.CngKey]::Open('" + key_name + "',"
            "[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,"
            "[Security.Cryptography.CngKeyOpenOptions]::MachineKey);"
            "$rsa=[Security.Cryptography.RSACng]::new($key);"
            "$public=[Security.Cryptography.X509Certificates.X509Certificate2]::new('" + str(path).replace("'", "''") + "');"
            "$cert=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($public,$rsa);"
            "$store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');"
            "try{$store.Open('ReadWrite');$store.Add($cert)}"
            "finally{$store.Dispose();$cert.Dispose();$public.Dispose();$rsa.Dispose();$key.Dispose()}"], check=True)
        return thumbprint

    @classmethod
    def remove_cng_key(cls, name):
        subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "if([Security.Cryptography.CngKey]::Exists('" + name + "',"
            "[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,"
            "[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){"
            "$k=[Security.Cryptography.CngKey]::Open('" + name + "',"
            "[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,"
            "[Security.Cryptography.CngKeyOpenOptions]::MachineKey);"
            "try{$k.Delete()}finally{$k.Dispose()}}"], check=True)

    @classmethod
    def remove_identity(cls):
        subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');"
            "try {$store.Open('ReadWrite');"
            "$thumbprints=@('" + "','".join(cls.thumbprints) + "');"
            "$certs=@($store.Certificates|Where-Object{$_.Thumbprint -in $thumbprints});"
            "foreach($cert in $certs){"
            "$rsa=$null;if($cert.Thumbprint -eq '" + cls.thumbprint + "'){"
            "$rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)};"
            "try {if($rsa -is [Security.Cryptography.RSACng]){$rsa.Key.Delete()}"
            "elseif($rsa -is [Security.Cryptography.RSACryptoServiceProvider]){$rsa.PersistKeyInCsp=$false}"
            "$store.Remove($cert)}finally{if($rsa){$rsa.Dispose()};$cert.Dispose()}}}"
            "finally{$store.Dispose()}"], check=True)

    def exchange(self, certificate="proxy.example", name="proxy.example",
                 root="test-root", thumbprint=None, stall=False, crl="valid", cancel=False,
                 tls13=False, reject_client=False, fragment=False, abrupt=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = (ssl.TLSVersion.TLSv1_3 if tls13 else ssl.TLSVersion.TLSv1_2)
        context.load_cert_chain(self.root / (certificate + ".pem"), self.root / (certificate + ".key"))
        context.load_verify_locations(self.root / ("other-root.pem" if reject_client else "test-root.pem"))
        context.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        received = bytearray()
        failures = []

        def serve():
            try:
                with listener:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(3)
                        if abrupt:
                            return
                        if stall:
                            while connection.recv(4096):
                                pass
                            return
                        if fragment:
                            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                            stream = context.wrap_bio(incoming, outgoing, server_side=True)

                            def flush():
                                while outgoing.pending:
                                    data = outgoing.read()
                                    for offset in range(0, len(data), 7):
                                        connection.sendall(data[offset:offset + 7])
                                        time.sleep(0.001)

                            while True:
                                try:
                                    stream.do_handshake()
                                    flush()
                                    break
                                except ssl.SSLWantReadError:
                                    flush()
                                    data = connection.recv(4096)
                                    if not data:
                                        raise ConnectionError("Peer closed during handshake")
                                    incoming.write(data)
                            while True:
                                try:
                                    data = stream.read(4096)
                                    if not data:
                                        return
                                    received.extend(data)
                                except ssl.SSLWantReadError:
                                    flush()
                                    data = connection.recv(4096)
                                    if not data:
                                        incoming.write_eof()
                                    else:
                                        incoming.write(data)
                            return
                        with context.wrap_socket(connection, server_side=True,
                                                 suppress_ragged_eofs=False) as stream:
                            while True:
                                chunk = stream.recv(4096)
                                if not chunk:
                                    break
                                received.extend(chunk)
            except (ssl.SSLError, ConnectionError, TimeoutError, OSError) as error:
                failures.append(type(error).__name__)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = time.monotonic()
        environment = dict(os.environ)
        if cancel:
            environment["MRBIG_TLS_CANCEL"] = "1"
        result = subprocess.run([self.probe, str(port), name,
            self.thumbprint if thumbprint is None else thumbprint,
            str(self.root / (root + ".pem")), "750" if stall and not cancel else "10000",
            str(self.root / (crl + ".crl"))], timeout=15, env=environment)
        elapsed = time.monotonic() - started
        thread.join(5)
        self.assertFalse(thread.is_alive(), "TLS test server did not terminate")
        return result.returncode, received, elapsed, failures

    def test_mutual_tls_large_report_and_clean_shutdown(self):
        code, received, _, failures = self.exchange()
        self.assertEqual(code, 0)
        self.assertEqual(received, b"x" * 65536)
        self.assertFalse(failures)

    def test_wrong_hostname_sends_no_report(self):
        code, received, _, _ = self.exchange(name="wrong.example")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_untrusted_ca_sends_no_report(self):
        code, received, _, _ = self.exchange(root="other-root")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_expired_server_sends_no_report(self):
        code, received, _, _ = self.exchange(certificate="expired.example", name="expired.example")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_wrong_server_eku_sends_no_report(self):
        code, received, _, _ = self.exchange(certificate="wrong-eku.example", name="wrong-eku.example")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_missing_client_identity_sends_no_report(self):
        code, received, _, _ = self.exchange(thumbprint="0" * 40)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_stalled_handshake_has_deadline(self):
        code, received, elapsed, _ = self.exchange(stall=True)
        self.assertEqual(code, 1)
        self.assertFalse(received)
        self.assertLess(elapsed, 3)

    def test_nonexportable_cng_machine_key(self):
        code, received, _, failures = self.exchange(thumbprint=self.cng_thumbprint)
        self.assertEqual(code, 0)
        self.assertEqual(len(received), 65536)
        self.assertFalse(failures)

    def test_renewed_certificate_selected(self):
        for thumbprint in [self.cng_thumbprint, self.renewed_thumbprint]:
            code, received, _, _ = self.exchange(thumbprint=thumbprint)
            self.assertEqual(code, 0)
            self.assertEqual(len(received), 65536)

    def test_tls13(self):
        code, received, _, failures = self.exchange(tls13=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(received), 65536)
        self.assertFalse(failures)

    def test_revoked_server(self):
        code, received, _, _ = self.exchange(crl="revoked")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_expired_crl(self):
        code, received, _, _ = self.exchange(certificate="fresh.example", name="fresh.example", crl="expired")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_missing_crl(self):
        code, received, _, _ = self.exchange(crl="missing")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_invalid_crl_signature(self):
        code, received, _, _ = self.exchange(crl="bad-signature")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_rejected_client(self):
        code, received, _, _ = self.exchange(reject_client=True)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_peer_disconnect(self):
        code, received, _, _ = self.exchange(abrupt=True)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_fragmented_handshake(self):
        code, received, _, failures = self.exchange(fragment=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(received), 65536)
        self.assertFalse(failures)

    def test_service_stop_cancels_handshake(self):
        code, received, elapsed, _ = self.exchange(stall=True, cancel=True)
        self.assertEqual(code, 1)
        self.assertFalse(received)
        self.assertLess(elapsed, 2)


if __name__ == "__main__":
    unittest.main()
