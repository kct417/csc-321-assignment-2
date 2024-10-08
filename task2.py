from pydoc import plain
from task1 import *
from Crypto.Cipher import AES


def url_encode(text):
    return text.replace("=", "%3D").replace(";", "%3B")


def url_decode(text):
    return text.replace("%3D", "=").replace("%3B", ";")


def submit(userdata, key, iv):
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    data = prefix + userdata + suffix
    data = url_encode(data)
    # encrypt (includes padding)
    return cbc_encrypt(key, bytes(data, "utf-8"), iv)


def verify(ciphertext, key, iv):
    plaintext = cbc_decrypt(key, ciphertext, iv)
    plaintext = plaintext.decode("utf-8")
    plaintext = url_decode(plaintext)
    return ";admin=true;" in plaintext


def tamper(ciphertext):
    arr = bytearray(ciphertext)
    # 16 is the start index of the block before the userdata block
    arr[16 + 0] ^= 1
    arr[16 + 6] ^= 1
    arr[16 + 11] ^= 1
    return bytes(arr)


if __name__ == "__main__":
    key = random_bytes(len=16)
    iv = random_bytes(len=16)
    # uses "A" to pad so that the :admin<true: is fully in a block
    userdata = "AAAAAA:admin<true:"
    # userdata = ";admin=true;"
    print(f"key: {key.hex()}, iv: {iv.hex()}, userdata: {userdata}")

    ciphertext = submit(userdata, key, iv)

    result = verify(ciphertext, key, iv)
    print("Untampered result of verify:", result)

    ciphertext = tamper(ciphertext)
    result = verify(ciphertext, key, iv)
    print("Tampered result of verify:", result)
