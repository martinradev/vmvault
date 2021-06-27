from Crypto.Cipher import AES

def asByteArray(bytes):
    s = "{ "
    s += ", ".join(hex(u) + "U" for u in bytes)
    s += " }"
    return s

key = b"A" * 16
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(b"B" * 16)
print(asByteArray(ciphertext))

key = b"".join(u.to_bytes(1, "little") for u in range(0, 16))
cipher = AES.new(key, AES.MODE_ECB)
data = b"".join(u.to_bytes(1, "little") for u in range(32, 128))
ciphertext = cipher.encrypt(data)
print(asByteArray(ciphertext))

key = b"A" * 16
iv = b"B" * 16
data = b"C" * 16
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(data)
print(asByteArray(ciphertext))

key = b"A" * 16
iv = b"B" * 16
data = b"C" * 96
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(data)
print(asByteArray(ciphertext))
