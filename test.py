from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

with open(f'pk2.pem', 'rb') as pem:
    pemlines = pem.read()
public_key = load_pem_public_key(pemlines, default_backend())

with open(f'sk2.pem', 'rb') as pem:
    pemlines = pem.read()
private_key = load_pem_private_key(pemlines, None, default_backend())

message = 'AAAAAAAA'.encode()

ciphertext = public_key.encrypt(
	message,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	)
)

plaintext = private_key.decrypt(
	ciphertext,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	)
)
print(plaintext)

next_ip = plaintext[0:4]
next_port = plaintext[4:6]
message = plaintext[6:]