"""Disposable Windows runner only: creates/removes one machine-store test identity.

Run: python -m unittest discover -s tests -p test_tls_windows.py -v
Requires cryptography and MRBIG_TLS_PROBE pointing to the compiled test harness.
No live infrastructure, administrator keys, or system-root trust changes.
"""
import datetime
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
        issue("proxy.example", ca, ca_key)
        issue("expired.example", ca, ca_key, expired=True)
        issue("wrong-eku.example", ca, ca_key, client=True)
        client, key = issue("client.example", ca, ca_key, client=True)
        cls.thumbprint = client.fingerprint(hashes.SHA1()).hex().upper()
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

    @classmethod
    def remove_identity(cls):
        subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');"
            "try {$store.Open('ReadWrite');"
            "$certs=$store.Certificates.Find('FindByThumbprint','" + cls.thumbprint + "',$false);"
            "foreach($cert in $certs){"
            "$rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert);"
            "try {if($rsa -is [Security.Cryptography.RSACng]){$rsa.Key.Delete()}"
            "elseif($rsa -is [Security.Cryptography.RSACryptoServiceProvider]){$rsa.PersistKeyInCsp=$false}"
            "$store.Remove($cert)}finally{if($rsa){$rsa.Dispose()};$cert.Dispose()}}}"
            "finally{$store.Dispose()}"], check=True)

    def exchange(self, certificate="proxy.example", name="proxy.example",
                 root="test-root", thumbprint=None, stall=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.root / (certificate + ".pem"), self.root / (certificate + ".key"))
        context.load_verify_locations(self.root / "test-root.pem")
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
                        if stall:
                            while connection.recv(4096):
                                pass
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
        result = subprocess.run([self.probe, str(port), name,
            self.thumbprint if thumbprint is None else thumbprint,
            str(self.root / (root + ".pem")), "750" if stall else "10000"], timeout=15)
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


if __name__ == "__main__":
    unittest.main()
