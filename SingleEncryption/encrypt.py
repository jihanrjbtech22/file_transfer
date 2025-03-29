from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Generate a random 16-byte AES key
key = get_random_bytes(16)

def encrypt_file(input_filename, output_filename, key):
    cipher = AES.new(key, AES.MODE_EAX)  # AES in EAX mode (secure and authenticated)
    
    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Encrypt and generate authentication tag

    with open(output_filename, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)  # Store nonce, tag, and encrypted data

    print(f"✅ File '{input_filename}' encrypted successfully as '{output_filename}'")

# Example Usage
encrypt_file("abc.txt", "abc_encrypted.txt", key)

# Save the key securely
with open("aes_key.bin", "wb") as f:
    f.write(key)
