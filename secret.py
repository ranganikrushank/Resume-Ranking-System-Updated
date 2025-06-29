import secrets

secret_key = secrets.token_hex(32)  # 64 characters long hex string
print("Secret Key:", secret_key)
