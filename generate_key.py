from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()

# Save to file
with open("fernet.key", "wb") as key_file:
    key_file.write(key)

print(f"Key saved to fernet.key: {key.decode()}")
