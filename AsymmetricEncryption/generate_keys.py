from Crypto.PublicKey import RSA

# Generate a 2048-bit RSA key pair
key = RSA.generate(2048)

# Save the Private Key
private_key = key.export_key()
with open("private_key.pem", "wb") as f:
    f.write(private_key)

# Save the Public Key
public_key = key.publickey().export_key()
with open("public_key.pem", "wb") as f:
    f.write(public_key)

print("✅ RSA Key Pair Generated: 'private_key.pem' and 'public_key.pem'")
