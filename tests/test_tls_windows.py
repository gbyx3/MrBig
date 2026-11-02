"""Disposable Windows runner only: creates/removes one machine-store test identity.

Run: python -m unittest discover -s tests -p test_tls_windows.py -v
Requires cryptography and MRBIG_TLS_PROBE pointing to the compiled test harness.
No live infrastructure, administrator keys, or system-root trust changes.
"""
import datetime
import contextlib
import hashlib
import json
import os
import shutil
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
        cls.cng_keys = {}
        cls.cng_serials = {}
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
        no_crl_ca, no_crl_key = issue("no-crl-root", ca=True)
        issue("unverifiable.example", no_crl_ca, no_crl_key)
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
        cls.expired_thumbprint = cls.create_cng_identity("expired-client", expired=True)
        revoked_entry = (x509.RevokedCertificateBuilder()
            .serial_number(cls.cng_serials[cls.cng_thumbprint])
            .revocation_date(now - datetime.timedelta(hours=1)).build())
        client_crl = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
            .last_update(now - datetime.timedelta(hours=1))
            .next_update(now + datetime.timedelta(days=2))
            .add_revoked_certificate(revoked_entry).sign(ca_key, hashes.SHA256()))
        (cls.root / "client-revocation-bundle.pem").write_bytes(
            ca.public_bytes(serialization.Encoding.PEM) + client_crl.public_bytes(serialization.Encoding.PEM))

    @classmethod
    def create_cng_identity(cls, name, expired=False):
        """Generate a persisted, non-exportable machine key; export only its CSR."""
        key_name = "MrBig-test-" + os.urandom(12).hex()
        cls.addClassCleanup(cls.remove_cng_key, key_name)
        result = subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop';"
            "$p=[Security.Cryptography.CngKeyCreationParameters]::new();"
            "$p.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;"
            "$p.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey;"
            "$p.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None;"
            "$p.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing;"
            "$p.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',"
            "[BitConverter]::GetBytes([int]3072),[Security.Cryptography.CngPropertyOptions]::None));"
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
        if csr.public_key().key_size < 2048:
            raise AssertionError("CNG fixture must use a modern RSA key size")
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(cls.ca.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=2))
                .not_valid_after(now + datetime.timedelta(days=-1 if expired else 2))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .sign(cls.ca_key, hashes.SHA256()))
        path = cls.root / (name + ".cer")
        path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
        cls.thumbprints.append(thumbprint)
        cls.cng_keys[thumbprint] = key_name
        cls.cng_serials[thumbprint] = cert.serial_number
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
                 tls13=False, reject_client=False, fragment=False, abrupt=False,
                  repeat=1, renew=None, deny_key=False, revoke_client=False,
                  close_stall=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = (ssl.TLSVersion.TLSv1_3 if tls13 else ssl.TLSVersion.TLSv1_2)
        context.load_cert_chain(self.root / (certificate + ".pem"), self.root / (certificate + ".key"))
        context.load_verify_locations(self.root / ("client-revocation-bundle.pem" if revoke_client else
                                      "other-root.pem" if reject_client else "test-root.pem"))
        if revoke_client:
            context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        context.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        received = bytearray()
        failures = []
        peers = []
        finished = threading.Event()

        def serve_one():
            try:
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
                    with context.wrap_socket(connection, server_side=True,
                                             suppress_ragged_eofs=False) as stream:
                        peers.append(x509.load_der_x509_certificate(stream.getpeercert(binary_form=True))
                                     .fingerprint(hashes.SHA1()).hex().upper())
                        while True:
                            chunk = stream.recv(4096)
                            if not chunk:
                                if close_stall:
                                    finished.wait(3)
                                break
                            received.extend(chunk)
            except (ssl.SSLError, ConnectionError, TimeoutError, OSError) as error:
                failures.append(getattr(error, "reason", type(error).__name__))
                if hasattr(error, "verify_code"):
                    failures.append("X509_VERIFY_CODE=" + str(error.verify_code))

        def serve():
            with listener:
                for _ in range(repeat):
                    if finished.is_set():
                        break
                    serve_one()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = time.monotonic()
        environment = dict(os.environ)
        environment["MRBIG_TLS_REPEAT"] = str(repeat)
        if renew:
            environment["MRBIG_TLS_RENEW_THUMBPRINT"] = renew
        if cancel:
            environment["MRBIG_TLS_CANCEL"] = "1"
        arguments = [str(port), name, self.thumbprint if thumbprint is None else thumbprint,
            str(self.root / (root + ".pem")), "750" if (stall or close_stall) and not cancel else "10000",
            str(self.root / (crl + ".crl")) if crl is not None else ""]
        if deny_key:
            argument_file = self.root / "denied-key-arguments.json"
            argument_file.write_text(json.dumps(arguments))
            command = ["pwsh.exe", "-NoProfile", "-NonInteractive", "-File",
                str(Path(__file__).with_name("with_denied_key.ps1")),
                "-KeyName", self.cng_keys[thumbprint], "-Probe", self.probe,
                "-ProbeArgumentsFile", str(argument_file)]
            stdin = None
        else:
            command, stdin = [self.probe, *arguments], None
        try:
            result = subprocess.run(command, input=stdin, timeout=60 if repeat > 1 or deny_key else 15,
                                    env=environment, capture_output=True, text=True)
        except subprocess.TimeoutExpired as error:
            self.fail("Disposable test driver timed out; diagnostic: " + str(error.stderr))
        self.last_probe_stdout = result.stdout
        self.last_probe_stderr = result.stderr
        elapsed = time.monotonic() - started
        finished.set()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "TLS test server did not terminate")
        self.last_peers = peers
        return result.returncode, received, elapsed, failures

    def test_mutual_tls_large_report_and_clean_shutdown(self):
        code, received, _, failures = self.exchange()
        self.assertEqual(code, 0)
        self.assertEqual(received, b"x" * 65536)
        self.assertFalse(failures)

    def test_peer_close_wait_has_deadline(self):
        code, received, elapsed, _ = self.exchange(close_stall=True)
        self.assertEqual(code, 1, self.last_probe_stderr)
        self.assertEqual(len(received), 65536)
        self.assertIn('stage=tcp-drain', self.last_probe_stderr)
        self.assertLess(elapsed, 3)

    def test_peer_close_wait_observes_cancellation(self):
        code, received, elapsed, _ = self.exchange(close_stall=True, cancel=True)
        self.assertEqual(code, 1, self.last_probe_stderr)
        self.assertEqual(len(received), 65536)
        self.assertIn('stage=tcp-drain', self.last_probe_stderr)
        self.assertLess(elapsed, 3)

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
        self.assertEqual(code, 0, failures)
        self.assertEqual(len(received), 65536)
        self.assertFalse(failures)

    def test_renewed_certificate_selected(self):
        for thumbprint in [self.cng_thumbprint, self.renewed_thumbprint]:
            code, received, _, _ = self.exchange(thumbprint=thumbprint)
            self.assertEqual(code, 0)
            self.assertEqual(len(received), 65536)

    def test_rotation_in_same_process(self):
        code, received, _, failures = self.exchange(thumbprint=self.cng_thumbprint,
            repeat=2, renew=self.renewed_thumbprint)
        self.assertEqual(code, 0, self.last_probe_stderr)
        self.assertEqual(len(received), 2 * 65536)
        self.assertEqual(self.last_peers, [self.cng_thumbprint, self.renewed_thumbprint])
        self.assertFalse(failures)

    def test_repeated_success_has_bounded_handles(self):
        code, received, _, failures = self.exchange(thumbprint=self.cng_thumbprint, repeat=30)
        self.assertEqual(code, 0, self.last_probe_stdout + self.last_probe_stderr)
        self.assertEqual(len(received), 30 * 65536)
        self.assertEqual(len(self.last_peers), 30)
        self.assertFalse(failures)

    def test_repeated_failure_has_bounded_handles(self):
        code, received, _, _ = self.exchange(name="wrong.example", repeat=30)
        self.assertEqual(code, 1, self.last_probe_stdout + self.last_probe_stderr)
        self.assertEqual(len(self.last_peers), 30)
        self.assertFalse(received)

    def test_machine_key_access_denied(self):
        code, received, _, _ = self.exchange(thumbprint=self.cng_thumbprint, deny_key=True)
        self.assertEqual(code, 1, self.last_probe_stderr)
        self.assertIn("stage=private-key-access", self.last_probe_stderr)
        self.assertIn("original ACL restored and read back", self.last_probe_stderr)
        self.assertFalse(received)
        code, received, _, failures = self.exchange(thumbprint=self.cng_thumbprint)
        self.assertEqual(code, 0, self.last_probe_stderr)
        self.assertEqual(len(received), 65536)
        self.assertFalse(failures)

    def start_stunnel(self, backend_port, tls13, version):
        """Disposable loopback receiver: same verification/relay shape as Xymon."""
        binary = os.environ.get('MRBIG_STUNNEL')
        if not binary:
            fixture = self.root / ('stunnel-fixture-' + version)
            executable = fixture / 'bin' / 'tstunnel.exe'
            if not executable.exists():
                digests = {
                    '5.74': '8ce19cc782a64b0cacf32356249265ed16b3888e3578454853f5497726778d76',
                    '5.82': '722c1ad626919af2b0034666b4d19cc4795e925c32f60e8f3c59af4fb3ad2dfc',
                }
                installer = self.root / ('stunnel-' + version + '-installer.exe')
                subprocess.run(['curl.exe', '--fail', '--location', '--silent', '--show-error',
                    'https://www.stunnel.org/archive/5.x/stunnel-' + version + '-win64-installer.exe',
                    '--output', str(installer)], check=True, capture_output=True, timeout=60)
                self.assertEqual(hashlib.sha256(installer.read_bytes()).hexdigest(),
                                 digests[version])
                subprocess.run(['7z.exe', 'x', str(installer), '-o' + str(fixture), '-y'],
                               check=True, capture_output=True, timeout=30)
            binary = str(executable)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        directory = self.root / ('stunnel-' + os.urandom(6).hex())
        directory.mkdir()
        log = directory / 'receiver.log'
        crl = x509.load_der_x509_crl((self.root / 'valid.crl').read_bytes())
        crl_file = directory / 'issuer.crl'
        crl_file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        config = directory / 'receiver.conf'
        config.write_text('\n'.join([
            'debug = debug', 'output = ' + str(log),
            'sslVersionMin = TLSv1.3' if tls13 else 'sslVersionMin = TLSv1.2',
            'sslVersionMax = TLSv1.3' if tls13 else 'sslVersionMax = TLSv1.2',
            '[from-clients]', 'accept = 127.0.0.1:' + str(port),
            'connect = 127.0.0.1:' + str(backend_port),
            'verifyChain = yes', 'checkHost = native-client',
            'CAfile = ' + str(self.root / 'test-root.pem'),
            'CRLfile = ' + str(crl_file),
            'cert = ' + str(self.root / 'proxy.example.pem'),
            'key = ' + str(self.root / 'proxy.example.key'), '']))
        # Extracted console binary only: no installer/service or machine trust edits.
        output = (directory / 'console.log').open('wb')
        process = subprocess.Popen([binary, str(config)],
                                   stdout=output, stderr=subprocess.STDOUT)
        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
            output.close()
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if log.exists() and 'Accepting new connections' in log.read_text(errors='replace'):
                return port, log
            if process.poll() is not None:
                break
            time.sleep(0.05)
        self.fail('Disposable stunnel failed to start: ' +
                  (log.read_text(errors='replace') if log.exists() else 'no receiver log'))

    def exercise_service(self, stall=False, tls13=False, stunnel=False,
                         stunnel_version='5.82', session_tickets=2):
        """Install only a uniquely named disposable service on the hosted CI VM."""
        service = "MrBigTlsTest" + os.urandom(6).hex()
        directory = self.root / (service + " with spaces")
        directory.mkdir()
        binary = directory / "mrbig.exe"
        shutil.copy2(os.environ["MRBIG_CLIENT"], binary)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = (
            ssl.TLSVersion.TLSv1_3 if tls13 else ssl.TLSVersion.TLSv1_2)
        context.num_tickets = session_tickets
        context.load_cert_chain(self.root / "proxy.example.pem", self.root / "proxy.example.key")
        context.load_verify_locations(self.root / "test-root.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        relay_log = None
        if stunnel:
            port, relay_log = self.start_stunnel(port, tls13, stunnel_version)
        finished = threading.Event()
        connected = threading.Event()
        report = threading.Event()
        count = [0]
        config = ["[mrbig]", "machine pilot.example", "sleep 300", "loop 300", "ttl 15",
            f"tls_display 127.0.0.1:{port} proxy.example",
            f"tls_client_thumbprint {self.cng_thumbprint}",
            f"tls_ca_file {self.root / 'test-root.pem'}",
            f"tls_crl_file {self.root / 'valid.crl'}",
            "option no_clientlog", "option no_cpu", "option no_memory", "option no_disk",
            "option no_procs", "option no_svcs", "option no_wmi", "option no_ext"]
        config_file = self.root / (service + " selected config.cfg")
        config_file.write_text("\n".join(config) + "\n")
        image_path = '"' + str(binary) + '" -c "' + str(config_file) + '"'

        def serve():
            with listener:
                while not finished.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return
                    with connection:
                        connected.set()
                        connection.settimeout(0.2 if stall else 3)
                        try:
                            if stall:
                                while not finished.is_set():
                                    try:
                                        if not connection.recv(4096):
                                            break
                                    except TimeoutError:
                                        continue
                                continue
                            transport = (contextlib.nullcontext(connection) if stunnel else
                                         context.wrap_socket(connection, server_side=True))
                            with transport as stream:
                                header = bytearray()
                                while True:
                                    chunk = stream.recv(4096)
                                    if not chunk:
                                        break
                                    if len(header) < 256:
                                        header.extend(chunk[:256 - len(header)])
                                if header.startswith((b"status ", b"status+")):
                                    count[0] += 1
                                    report.set()
                        except (ssl.SSLError, OSError):
                            pass

        def powershell(script):
            result = subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop';" + script], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        installed = False
        try:
            subprocess.run([str(binary), "-i" + service], check=True, timeout=10)
            installed = True
            installed_path = json.loads(powershell(
                "$s=Get-CimInstance Win32_Service -Filter \"Name='" + service + "'\";"
                "@{path=$s.PathName}|ConvertTo-Json -Compress"))
            self.assertEqual(installed_path["path"], '"' + str(binary) + '"')
            subprocess.run(["sc.exe", "config", service, "binPath=", image_path],
                           check=True, timeout=10)
            for _ in range(1 if stall else 2):
                report.clear()
                connected.clear()
                metadata = json.loads(powershell(
                    "Start-Service -Name '" + service + "';"
                    "$s=Get-CimInstance Win32_Service -Filter \"Name='" + service + "'\";"
                    "@{processId=$s.ProcessId;path=$s.PathName}|ConvertTo-Json -Compress"))
                self.assertEqual(metadata["path"], image_path)
                self.assertGreater(metadata["processId"], 0)
                self.assertTrue((connected if stall else report).wait(10),
                                "Service did not establish the expected reporting connection" +
                                ('\n' + relay_log.read_text(errors='replace')[-12000:]
                                 if relay_log else ''))
                started = time.monotonic()
                powershell("Stop-Service -Name '" + service + "';"
                    "$s=Get-Service -Name '" + service + "';"
                    "$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(8));"
                    "Wait-Process -Id " + str(metadata["processId"]) + " -Timeout 5 -ErrorAction SilentlyContinue;"
                    "if(Get-Process -Id " + str(metadata["processId"]) +
                    " -ErrorAction SilentlyContinue){throw 'Agent process survived STOPPED'}")
                self.assertLess(time.monotonic() - started, 8)
            if not stall:
                self.assertGreaterEqual(count[0], 2)
        finally:
            if installed:
                subprocess.run(["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "Stop-Service -Name '" + service + "' -ErrorAction SilentlyContinue"], timeout=15)
                subprocess.run(["sc.exe", "delete", service], check=True, timeout=10)
            finished.set()
            listener.close()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "Disposable service listener did not exit")

    def test_service_start_stop_restart(self):
        self.exercise_service()

    def test_service_tls13_start_stop_restart(self):
        self.exercise_service(tls13=True)

    def test_service_stunnel_tls12(self):
        self.exercise_service(stunnel=True)

    def test_service_stunnel_tls13(self):
        self.exercise_service(stunnel=True, tls13=True)

    def test_service_stunnel_574_tls12(self):
        self.exercise_service(stunnel=True, stunnel_version='5.74')

    def test_service_stunnel_574_tls13(self):
        self.exercise_service(stunnel=True, tls13=True, stunnel_version='5.74')

    def test_service_tls13_unread_session_tickets(self):
        self.exercise_service(tls13=True, session_tickets=16)

    def test_service_stop_during_stalled_tls(self):
        self.exercise_service(stall=True)

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

    def test_unknown_revocation_without_crl_fails_closed(self):
        code, received, _, _ = self.exchange(certificate="unverifiable.example",
            name="unverifiable.example", root="no-crl-root", crl=None)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_expired_client_identity(self):
        code, received, _, _ = self.exchange(thumbprint=self.expired_thumbprint)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_proxy_connection_refused(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        started = time.monotonic()
        result = subprocess.run([self.probe, str(port), "proxy.example", self.thumbprint,
            str(self.root / "test-root.pem"), "5000", str(self.root / "valid.crl")],
            timeout=8, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("stage=connect", result.stderr)
        self.assertLess(time.monotonic() - started, 3)

    def test_invalid_crl_signature(self):
        code, received, _, _ = self.exchange(crl="bad-signature")
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_rejected_client(self):
        code, received, _, _ = self.exchange(reject_client=True)
        self.assertEqual(code, 1)
        self.assertFalse(received)

    def test_receiver_rejects_revoked_client(self):
        code, received, _, failures = self.exchange(thumbprint=self.cng_thumbprint, revoke_client=True)
        self.assertEqual(code, 1, self.last_probe_stderr)
        self.assertFalse(received)
        self.assertIn("X509_VERIFY_CODE=23", failures)

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
