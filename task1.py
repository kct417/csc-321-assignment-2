import os
from Crypto.Cipher import AES


def read_bmp_header(filename):
    with open(filename, "rb") as f:
        return f.read(54), f.read()


def encrypt_image(image_filename, mode, key=None, iv=None):
    header, data = read_bmp_header(image_filename)

    if key is None:
        key = generate_bytes(16)
    if iv is None:
        iv = generate_bytes(16)

    match mode:
        case "ecb":
            data = ecb_encrypt(key, data)

        case "cbc":
            data = cbc_encrypt(key, data, iv)

    with open("encrypted_" + image_filename + "_" + mode, "wb") as f:
        if mode == "cbc":
            f.write(header + iv + data)
        else:
            f.write(header + data)


def decrypt_image(image_filename, mode, key, iv=None):
    header, data = read_bmp_header(image_filename)

    if iv is None:
        iv = data[0:16]
        data = data[16:]

    match mode:
        case "ecb":
            data = ecb_decrypt(key, data)

        case "cbc":
            data = cbc_decrypt(key, data, iv)

    with open("decrypted_" + image_filename + "_" + mode, "wb") as f:
        f.write(header + data)


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    plaintext = pad_text(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    block = []

    while plaintext:
        block.append(cipher.encrypt(plaintext[0:16]))
        plaintext = plaintext[16:]

    return b"".join(block)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    block = []

    while ciphertext:
        block.append(cipher.decrypt(ciphertext[:16]))
        ciphertext = ciphertext[16:]

    return remove_padding(b"".join(block))


def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    plaintext = pad_text(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    block = []

    iv_bits = int.from_bytes(iv, "big")
    plaintext_bits = int.from_bytes(plaintext[:16], "big")

    plaintext = plaintext[16:]
    xor = iv_bits ^ plaintext_bits

    while plaintext:
        block.append(cipher.encrypt(xor.to_bytes(16, "big")))
        xor = int.from_bytes(block[-1], "big") ^ int.from_bytes(plaintext[:16], "big")
        plaintext = plaintext[16:]

    return b"".join(block)


def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    block = []

    iv_bits = int.from_bytes(iv, "big")
    ciphertext_bits = int.from_bytes(ciphertext[0:16], "big")

    return b""


def generate_bytes(b: int) -> bytes:
    return os.urandom(b)


def pad_text(plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    return plaintext + bytes([pad] * pad)


def remove_padding(plaintext: bytes) -> bytes:
    return plaintext[: -plaintext[-1]]


def main() -> None:
    return


if __name__ == "__main__":
    main()
