import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timezone
import OpenSSL

class SSLTLSAnalyzer:
    def __init__(self, session):
        self.session=session
        self.results = {}

    async def analyze(self,url):
        try:
            async with self.session.get(url) as response:
                self.analyze_connection(response)
                await self.analyze_certificate(response)
                self.analyze_cipher_suite(response)
        except aiohttp.ClientSSLError as e:
            self.results['error'] = f"SSL Error: {str(e)}"
        except aiohttp.ClientError as e:
            self.results['error'] = f"Connection Error: {str(e)}"
        except Exception as e:
            self.results['error'] = f"Unexpected Error: {str(e)}"

        self.results['security_score'] = self.get_security_score()
        return self.results

    def analyze_connection(self, response):
        self.results['protocol'] = response.version()
        self.results['cipher'] = response.cipher()
        self.results['tls_version'] = response.connection.transport.get_extra_info('ssl_object').version()

    async def analyze_certificate(self, response):
        ssl_object = response.connection.transport.get_extra_info('ssl_object')
        cert_binary = ssl_object.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_binary, default_backend())
        openssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)


        self.results['certificate'] = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'version': cert.version,
            'not_valid_before': cert.not_valid_before,
            'not_valid_after': cert.not_valid_after,
            'serial_number': cert.serial_number,
            'key_size': cert.public_key().key_size,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'subject_alternative_names': self.get_sans(cert),
            'key_usage': self.get_key_usage(cert),
            'extended_key_usage': self.get_extended_key_usage(cert),
            'ocsp_urls': self.get_ocsp_urls(cert),
            'crl_distribution_points': self.get_crl_distribution_points(cert),
        }

        self.analyze_key_type(cert)
        self.check_certificate_validity(cert)
        self.check_key_strength(cert)
        self.check_signature_algorithm(cert)
        self.check_certificate_transparency(openssl_cert)

    def analyze_cipher_suite(self, response):
        ssl_object = response.connection.transport.get_extra_info('ssl_object')
        cipher = ssl_object.cipher()
        self.results['cipher_suite'] = {
            'name': cipher[0],
            'protocol': cipher[1],
            'key_size': cipher[2]
        }
        self.check_cipher_strength(cipher[0])

    def get_sans(self, cert):
        try:
            san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [str(name) for name in san.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_key_usage(self, cert):
        try:
            key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            return [usage for usage, value in key_usage.value.items() if value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_extended_key_usage(self, cert):
        try:
            ext_key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            return [usage._name for usage in ext_key_usage.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_ocsp_urls(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            return [str(desc.access_location) for desc in aia.value if isinstance(desc, x509.AccessDescription) and desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_crl_distribution_points(self, cert):
        try:
            crl_dp = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            return [str(point.full_name[0]) for point in crl_dp.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def analyze_key_type(self, cert):
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.results['certificate']['key_type'] = 'RSA'
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.results['certificate']['key_type'] = 'ECC'
            self.results['certificate']['curve'] = public_key.curve.name

    def check_certificate_validity(self, cert):
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before:
            self.results['certificate']['status'] = "Not yet valid"
        elif now > cert.not_valid_after:
            self.results['certificate']['status'] = "Expired"
        else:
            self.results['certificate']['status'] = "Valid"

    def check_key_strength(self, cert):
        key_size = cert.public_key().key_size
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            if key_size < 2048:
                self.add_warning("Weak RSA key size (< 2048 bits)")
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            if key_size < 256:
                self.add_warning("Weak ECC key size (< 256 bits)")

    def check_signature_algorithm(self, cert):
        weak_algorithms = ['md5', 'sha1']
        if any(alg in cert.signature_algorithm_oid._name.lower() for alg in weak_algorithms):
            self.add_warning("Weak signature algorithm")

    def check_certificate_transparency(self, openssl_cert):
        scts = openssl_cert.get_extension_count()
        for i in range(scts):
            ext = openssl_cert.get_extension(i)
            if ext.get_short_name() == b'CT Precertificate SCTs':
                self.results['certificate']['sct_count'] = len(ext.get_data())
                return
        self.add_warning("No Certificate Transparency SCTs found")

    def check_cipher_strength(self, cipher_name):
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
        if any(weak in cipher_name for weak in weak_ciphers):
            self.add_warning(f"Weak cipher suite: {cipher_name}")

    def add_warning(self, warning):
        if 'warnings' not in self.results:
            self.results['warnings'] = []
        self.results['warnings'].append(warning)

    def get_security_score(self):
        score = 0

        # Check TLS version
        if self.results['tls_version'] == 'TLSv1.3':
            score += 3
        elif self.results['tls_version'] == 'TLSv1.2':
            score += 2
        elif self.results['tls_version'] == 'TLSv1.1':
            score += 1

        # Check certificate validity
        if self.results['certificate']['status'] == "Valid":
            score += 2

        # Check key size
        if self.results['certificate']['key_size'] >= 2048:
            score += 2
        elif self.results['certificate']['key_size'] >= 1024:
            score += 1

        # Check signature algorithm
        if 'sha256' in self.results['certificate']['signature_algorithm'].lower():
            score += 1

        # Check for Certificate Transparency
        if 'sct_count' in self.results['certificate'] and self.results['certificate']['sct_count'] > 0:
            score += 1

        # Deduct points for warnings
        score -= len(self.results.get('warnings', []))

        return max(0, min(score))