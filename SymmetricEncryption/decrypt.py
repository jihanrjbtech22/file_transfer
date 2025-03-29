from Crypto.Cipher import AES

def decrypt_file(input_filename, output_filename, key_filename):
    with open(key_filename, "rb") as f:
        key = f.read()  # Load the saved AES key

    with open(input_filename, "rb") as f:
        nonce = f.read(16)  # Read nonce (first 16 bytes)
        tag = f.read(16)  # Read tag (next 16 bytes)
        ciphertext = f.read()  # Read encrypted data

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify

    with open(output_filename, "wb") as f:
        f.write(plaintext)

    print(f"✅ File '{input_filename}' decrypted successfully as '{output_filename}'")

# Example Usage
decrypt_file("abc_encrypted.txt", "abc_decrypted.txt", "aes_key.bin")
