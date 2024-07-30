import asyncio
import aiohttp
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import OpenSSL.crypto
from typing import Dict, Any, List, Optional
import ssl

class SSLTLSAnalyzer:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.results: Dict[str, Any] = {
            'url': '',
            'score': 0,
            'findings': set(),
            'warnings': set(),
            'vulnerabilities': set(),
            'details': {
                'protocol': '',
                'cipher': '',
                'tls_version': '',
                'certificate': {},
                'cipher_suite': {}
            }
        }

    def add_finding(self, finding: str) -> None:
        self.results['findings'].add(finding)

    def add_warning(self, warning: str) -> None:
        self.results['warnings'].add(warning)

    def add_vulnerability(self, vulnerability: str) -> None:
        self.results['vulnerabilities'].add(vulnerability)

    def update_score(self, value: float) -> None:
        self.results['score'] += value

    def add_detail(self, category: str, key: str, value: Any) -> None:
        if category not in self.results['details']:
            self.results['details'][category] = {}
        self.results['details'][category][key] = value

    async def analyze(self, url: str) -> Dict[str, Any]:
        self.results['url'] = url
        try:
            async with self.session.get(url, ssl=ssl.create_default_context()) as response:
                await self.analyze_connection(response)
                await self.analyze_certificate(response)
                await self.analyze_cipher_suite(response)
        except aiohttp.ClientSSLError as e:
            self.add_vulnerability(f"SSL Error: {str(e)}")
        except aiohttp.ClientConnectorError as e:
            self.add_vulnerability(f"Connection Error: {str(e)}")
        except Exception as e:
            self.add_vulnerability(f"Unexpected error: {str(e)}")

        return self.generate_report()

    async def analyze_connection(self, response: aiohttp.ClientResponse) -> None:
        try:
            ssl_object = response.connection.transport.get_extra_info('ssl_object')
            if ssl_object:
                protocol_version = ssl_object.version()
                self.add_detail('protocol', 'version', protocol_version)
                self.add_detail('tls_version', 'version', protocol_version)
                
                # Score TLS version
                if protocol_version == 'TLSv1.3':
                    self.update_score(3)
                    self.add_finding("TLS 1.3 in use")
                elif protocol_version == 'TLSv1.2':
                    self.update_score(2)
                    self.add_finding("TLS 1.2 in use")
                else:
                    self.add_warning("Outdated TLS version in use")
            else:
                self.add_vulnerability("No SSL object found in connection")
        except Exception as e:
            self.add_vulnerability(f"Error analyzing connection: {str(e)}")

    async def analyze_certificate(self, response: aiohttp.ClientResponse) -> None:
        try:
            ssl_object = response.connection.transport.get_extra_info('ssl_object')
            if not ssl_object:
                self.add_vulnerability("No SSL object found in connection")
                return

            cert_binary = ssl_object.getpeercert(binary_form=True)
            if not cert_binary:
                self.add_vulnerability("No certificate found")
                return

            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            openssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)

            cert_details = {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'version': cert.version,
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'serial_number': str(cert.serial_number),
                'key_size': cert.public_key().key_size,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'subject_alternative_names': self.get_sans(cert),
                'key_usage': self.get_key_usage(cert),
                'extended_key_usage': self.get_extended_key_usage(cert),
                'ocsp_urls': self.get_ocsp_urls(cert),
                'crl_distribution_points': self.get_crl_distribution_points(cert),
            }

            self.add_detail('certificate', 'details', cert_details)

            self.analyze_key_type(cert)
            self.check_certificate_validity(cert)
            self.check_key_strength(cert)
            self.check_signature_algorithm(cert)
            self.check_certificate_transparency(openssl_cert)
        except Exception as e:
            self.add_vulnerability(f"Error analyzing certificate: {str(e)}")

    async def analyze_cipher_suite(self, response: aiohttp.ClientResponse) -> None:
        try:
            ssl_object = response.connection.transport.get_extra_info('ssl_object')
            if ssl_object:
                cipher = ssl_object.cipher()
                cipher_suite = {
                    'name': cipher[0],
                    'protocol': cipher[1],
                    'key_size': cipher[2]
                }
                self.add_detail('cipher_suite', 'details', cipher_suite)
                self.check_cipher_strength(cipher[0])
            else:
                self.add_vulnerability("No SSL object found in connection")
        except Exception as e:
            self.add_vulnerability(f"Error analyzing cipher suite: {str(e)}")

    def get_sans(self, cert: x509.Certificate) -> List[str]:
        try:
            san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [str(name) for name in san.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_key_usage(self, cert: x509.Certificate) -> List[str]:
        try:
            key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            return [usage for usage, value in key_usage.value.items() if value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_extended_key_usage(self, cert: x509.Certificate) -> List[str]:
        try:
            ext_key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            return [usage._name for usage in ext_key_usage.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_ocsp_urls(self, cert: x509.Certificate) -> List[str]:
        try:
            aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            return [str(desc.access_location) for desc in aia.value if isinstance(desc, x509.AccessDescription) and desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        except x509.extensions.ExtensionNotFound:
            return []

    def get_crl_distribution_points(self, cert: x509.Certificate) -> List[str]:
        try:
            crl_dp = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            return [str(point.full_name[0]) for point in crl_dp.value]
        except x509.extensions.ExtensionNotFound:
            return []

    def analyze_key_type(self, cert: x509.Certificate) -> None:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.add_detail('certificate', 'key_type', 'RSA')
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.add_detail('certificate', 'key_type', 'ECC')
            self.add_detail('certificate', 'curve', public_key.curve.name)

    def check_certificate_validity(self, cert: x509.Certificate) -> None:
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before:
            self.add_warning("Certificate not yet valid")
            self.update_score(-2)
        elif now > cert.not_valid_after:
            self.add_warning("Certificate expired")
            self.update_score(-3)
        else:
            self.add_finding("Certificate is valid")
            self.update_score(2)

    def check_key_strength(self, cert: x509.Certificate) -> None:
        key_size = cert.public_key().key_size
        if isinstance(cert.public_key(), rsa.RSAPublicKey):
            if key_size >= 4096:
                self.add_finding("Strong RSA key size (>= 4096 bits)")
                self.update_score(3)
            elif key_size >= 2048:
                self.add_finding("Adequate RSA key size (>= 2048 bits)")
                self.update_score(2)
            else:
                self.add_warning("Weak RSA key size (< 2048 bits)")
                self.update_score(-2)
        elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            if key_size >= 384:
                self.add_finding("Strong ECC key size (>= 384 bits)")
                self.update_score(3)
            elif key_size >= 256:
                self.add_finding("Adequate ECC key size (>= 256 bits)")
                self.update_score(2)
            else:
                self.add_warning("Weak ECC key size (< 256 bits)")
                self.update_score(-2)

    def check_signature_algorithm(self, cert: x509.Certificate) -> None:
        weak_algorithms = ['md5', 'sha1']
        if any(alg in cert.signature_algorithm_oid._name.lower() for alg in weak_algorithms):
            self.add_warning("Weak signature algorithm")
            self.update_score(-2)
        else:
            self.add_finding("Strong signature algorithm")
            self.update_score(2)

    def check_certificate_transparency(self, openssl_cert: OpenSSL.crypto.X509) -> None:
        scts = openssl_cert.get_extension_count()
        for i in range(scts):
            ext = openssl_cert.get_extension(i)
            if ext.get_short_name() == b'CT Precertificate SCTs':
                self.add_finding("Certificate Transparency SCTs found")
                self.update_score(2)
                return
        self.add_warning("No Certificate Transparency SCTs found")
        self.update_score(-1)

    def check_cipher_strength(self, cipher_name: str) -> None:
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
        if any(weak in cipher_name for weak in weak_ciphers):
            self.add_warning(f"Weak cipher suite: {cipher_name}")
            self.update_score(-2)
        else:
            self.add_finding(f"Strong cipher suite: {cipher_name}")
            self.update_score(2)

    def generate_report(self) -> Dict[str, Any]:
        overall_assessment = "Low security risk"
        if self.results['score'] < 0:
            overall_assessment = "High security risk - immediate action recommended"
        elif self.results['score'] < 5:
            overall_assessment = "Moderate security risk - improvements needed"
        elif self.results['score'] >= 10:
            overall_assessment = "Excellent security - no immediate action required"

        return {
            "url": self.results['url'],
            "score": self.results['score'],
            "findings": list(self.results['findings']),
            "warnings": list(self.results['warnings']),
            "vulnerabilities": list(self.results['vulnerabilities']),
            "details": self.results['details'],
            "overall_assessment": overall_assessment
        }