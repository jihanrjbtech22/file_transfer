from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_file(input_file, output_file, public_key_file):
    # Load the Public Key
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(public_key)  # Use RSA with OAEP padding

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher_rsa.encrypt(plaintext)  # Encrypt the file

    with open(output_file, "wb") as f:
        f.write(ciphertext)

    print(f"🔒 File '{input_file}' encrypted successfully as '{output_file}'")

# Encrypt the file using the public key
encrypt_file("abc.txt", "abc_encrypted.bin", "public_key.pem")
