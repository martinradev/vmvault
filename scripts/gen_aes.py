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
print(key, data)
ciphertext = cipher.encrypt(data)
print(asByteArray(ciphertext))
