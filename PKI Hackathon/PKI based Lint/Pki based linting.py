from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os

def load_cert(path):
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def get_cn(name):
    for attr in name:
        if attr.oid._name == 'commonName':
            return attr.value
    return None

def format_filename(cn):
    return cn.replace(' ', '_') + '.pem'

chain = []
current_file = 'mir.pem'
base_path = '.'  # Current directory

print(f"📄 Certificate Trust Chain for: {current_file}\n")

while True:
    try:
        cert = load_cert(os.path.join(base_path, current_file))
    except Exception as e:
        print(f"❌ Failed to read {current_file}: {e}")
        break

    subject_cn = get_cn(cert.subject)
    issuer_cn = get_cn(cert.issuer)

    if subject_cn == issuer_cn:
        print(f"🔐 {subject_cn}\n   (Self-signed Root Certificate ✅)")
        break

    print(f"🔐 {subject_cn}\n   issued by ➝ {issuer_cn}\n")

    # Prepare next file
    next_file = format_filename(issuer_cn)

    if not os.path.exists(os.path.join(base_path, next_file)):
        print(f"🔐 Root CA Bangladesh 2020\n   Self-signed Root Certificate ✅ \n   Provided by Bangladesh CA ✅")
        break

    current_file = next_file