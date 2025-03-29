from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_file(input_file, output_file, private_key_file):
    # Load the Private Key
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open(input_file, "rb") as f:
        ciphertext = f.read()

    plaintext = cipher_rsa.decrypt(ciphertext)  # Decrypt the file

    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"✅ File '{input_file}' decrypted successfully as '{output_file}'")

# Decrypt the file using the private key
decrypt_file("abc_encrypted.bin", "abc_decrypted.txt", "private_key.pem")
