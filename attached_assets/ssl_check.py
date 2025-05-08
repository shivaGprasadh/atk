import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def fetch_certificate(domain, port=443):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(5.0)
    conn.connect((domain, port))
    der_cert = conn.getpeercert(binary_form=True)
    conn.close()
    return der_cert


def parse_certificate(der_cert):
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    now = datetime.now(timezone.utc)

    # Get expiry days
    days_left = (cert.not_valid_after_utc - now).days

    # Fingerprints
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    sha1_fp = cert.fingerprint(hashes.SHA1()).hex().upper()

    # Public key info
    public_key = cert.public_key()
    pubkey_type = public_key.__class__.__name__
    pubkey_size = getattr(public_key, "key_size", "Unknown")

    # AIA - Authority Info Access
    try:
        aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia_urls = [desc.access_location.value for desc in aia_ext.value]
    except x509.ExtensionNotFound:
        aia_urls = ["Not present"]

    # Certificate Policies
    try:
        cert_policies_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CERTIFICATE_POLICIES)
        cert_policies = [str(policy.policy_identifier) for policy in cert_policies_ext.value]
    except x509.ExtensionNotFound:
        cert_policies = ["Not present"]

    return {
        "Subject": cert.subject.rfc4514_string(),
        "Issuer (CA)": cert.issuer.rfc4514_string(),
        "Signature Algorithm": cert.signature_hash_algorithm.name,
        "Valid From": cert.not_valid_before_utc,
        "Valid To": cert.not_valid_after_utc,
        "Days Until Expiry": days_left,
        "SHA256 Fingerprint": sha256_fp,
        "SHA1 Fingerprint": sha1_fp,
        "Public Key Type": pubkey_type,
        "Public Key Size": pubkey_size,
        "Authority Info Access (AIA)": aia_urls,
        "Certificate Policies": cert_policies
    }


# Example usage
if __name__ == "__main__":
    domain = "experience.com"  # 🔄 Replace with your target domain
    try:
        der_cert = fetch_certificate(domain)
        cert_info = parse_certificate(der_cert)
        for key, value in cert_info.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"Error: {e}")
