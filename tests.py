import asyncio
import aiohttp
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import OpenSSL.crypto
import ssl

class SSLTLSAnalyzer:
    def __init__(self, session):
        self.session = session
        self.reset_results()
    def reset_results(self):
        self.results = {
            'url': '',
            'score': 0,
            'findings': set(),
            'warnings': set(),
            'vulnerabilities': [],
            'details': {
                'protocol': '',
                'cipher': '',
                'tls_version': '',
                'certificate': {},
                'cipher_suite': {}
            }
        }

    def add_finding(self, finding):
        self.results['findings'].add(finding)

    def add_warning(self, warning):
        self.results['warnings'].add(warning)

    def add_vulnerability(self, vulnerability):
        self.results['vulnerabilities'].append(vulnerability)

    def update_score(self, value):
        self.results['score'] += value

    def add_detail(self, category, key, value):
        if category not in self.results['details']:
            self.results['details'][category] = {}
        self.results['details'][category][key] = str(value)

    async def analyze(self, url):
        self.reset_results()
        self.results['url'] = url
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with self.session.get(url, ssl=ssl_context) as response:
                self.analyze_connection(response)
                await self.analyze_certificate(response)
                self.analyze_cipher_suite(response)
        except aiohttp.ClientSSLError as e:
            self.add_warning(f"SSL Error: {str(e)}")
        except Exception as e:
            self.add_warning(f"Error during SSL/TLS analysis: {str(e)}")
        
        self.calculate_security_score()
        return self.generate_report()

    def analyze_connection(self, response):
        ssl_object = response.connection.transport.get_extra_info('ssl_object')
        if ssl_object:
            self.add_detail('protocol', 'version', ssl_object.version())
            self.add_detail('cipher', 'name', ssl_object.cipher()[0])
            self.add_detail('tls_version', 'version', ssl_object.version())
        else:
            self.add_warning("No SSL connection established")

    async def analyze_certificate(self, response):
        ssl_object = response.connection.transport.get_extra_info('ssl_object')
        if not ssl_object:
            self.add_warning("No SSL connection established")
            return

        try:
            cert_binary = ssl_object.getpeercert(binary_form=True)
            if not cert_binary:
                self.add_warning("No certificate found")
                return

            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            openssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)

            self.add_detail('certificate', 'subject', cert.subject.rfc4514_string())
            self.add_detail('certificate', 'issuer', cert.issuer.rfc4514_string())
            self.add_detail('certificate', 'version', cert.version)
            self.add_detail('certificate', 'not_valid_before', cert.not_valid_before.isoformat())
            self.add_detail('certificate', 'not_valid_after', cert.not_valid_after.isoformat())
            self.add_detail('certificate', 'serial_number', str(cert.serial_number))

            self.analyze_key_type(cert)
            self.check_certificate_validity(cert)
            self.check_key_strength(cert)
            self.check_signature_algorithm(cert)
            self.check_certificate_transparency(openssl_cert)
        except Exception as e:
            self.add_warning(f"Error analyzing certificate: {str(e)}")
            print(f"Certificate analysis error: {str(e)}")

    def analyze_cipher_suite(self, response):
        ssl_object = response.connection.transport.get_extra_info('ssl_object')
        if ssl_object:
            cipher = ssl_object.cipher()
            if cipher:
                self.add_detail('cipher_suite', 'name', cipher[0])
                self.add_detail('cipher_suite', 'protocol', cipher[1])
                self.add_detail('cipher_suite', 'key_size', str(cipher[2]))
                self.check_cipher_strength(cipher[0])
        else:
            self.add_warning("No SSL connection established")

    def analyze_key_type(self, cert):
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.add_detail('certificate', 'key_type', 'RSA')
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.add_detail('certificate', 'key_type', 'ECC')
            self.add_detail('certificate', 'curve', public_key.curve.name)

    def check_certificate_validity(self, cert):
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before:
            self.add_detail('certificate', 'status', "Not yet valid")
        elif now > cert.not_valid_after:
            self.add_detail('certificate', 'status', "Expired")
        else:
            self.add_detail('certificate', 'status', "Valid")

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
                self.add_detail('certificate', 'sct_count', str(len(ext.get_data())))
                return
        self.add_warning("No Certificate Transparency SCTs found")

    def check_cipher_strength(self, cipher_name):
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
        if any(weak in cipher_name for weak in weak_ciphers):
            self.add_warning(f"Weak cipher suite: {cipher_name}")

    def calculate_security_score(self):
        if self.results['details']['tls_version'] == 'TLSv1.3':
            self.update_score(3)
        elif self.results['details']['tls_version'] == 'TLSv1.2':
            self.update_score(2)
        elif self.results['details']['tls_version'] == 'TLSv1.1':
            self.update_score(1)

        if self.results['details']['certificate'].get('status') == "Valid":
            self.update_score(2)

        if self.results['details']['certificate'].get('key_size', 0) >= 2048:
            self.update_score(2)
        elif self.results['details']['certificate'].get('key_size', 0) >= 1024:
            self.update_score(1)

        if 'sha256' in self.results['details']['certificate'].get('signature_algorithm', '').lower():
            self.update_score(1)

        if int(self.results['details']['certificate'].get('sct_count', 0)) > 0:
            self.update_score(1)

        self.update_score(-len(self.results['warnings']))

        self.results['score'] = max(0, min(self.results['score'], 10))

    def generate_report(self):
        overall_assessment = "Poor SSL/TLS security"
        if self.results['score'] >= 8:
            overall_assessment = "Excellent SSL/TLS security"
        elif self.results['score'] >= 6:
            overall_assessment = "Good SSL/TLS security"
        elif self.results['score'] >= 4:
            overall_assessment = "Moderate SSL/TLS security, improvements recommended"

        return {
            "url": self.results['url'],
            "score": self.results['score'],
            "findings": list(self.results['findings']),
            "warnings": list(self.results['warnings']),
            "vulnerabilities": self.results['vulnerabilities'],
            "details": self.results['details'],
            "overall_assessment": overall_assessment
        }