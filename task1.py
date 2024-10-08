import os
from Crypto.Cipher import AES


# Read the header of the BMP file
def read_bmp_header(filename):
    with open(filename, "rb") as f:
        return f.read(54), f.read()


# Encrypt the image using ECB or CBC mode
# Save the encrypted image to a new file
def encrypt_image(image_filename: str, mode: str, key: bytes, iv=None):
    if mode not in ["ecb", "cbc"]:
        raise ValueError("Invalid mode")
    header, data = read_bmp_header(image_filename)

    if iv is None and mode == "cbc":
        iv = random_bytes(len=16)

    data = ecb_encrypt(key, data) if mode == "ecb" else cbc_encrypt(key, data, iv)

    image_filename = image_filename[: -len(".bmp")]
    with open(f"encrypted_{image_filename}_{mode}.bmp", "wb") as f:
        f.write(header + (iv if iv is not None else b"") + data)


# Decrypt the image using ECB or CBC mode
# Save the decrypted image to a new file
def decrypt_image(image_filename: str, mode: str, key: bytes, iv=None):
    if mode not in ["ecb", "cbc"]:
        raise ValueError("Invalid mode")
    header, data = read_bmp_header(image_filename)

    if iv is None and mode == "cbc":
        iv = data[:16]
        data = data[16:]

    data = ecb_decrypt(key, data) if mode == "ecb" else cbc_decrypt(key, data, iv)

    image_filename = image_filename[len("encrypted_") : -len(f"_{mode}.bmp")]
    with open(f"decrypted_{image_filename}_{mode}.bmp", "wb") as f:
        f.write(header + data)


# Encrypt the plaintext using ECB mode
# Return the ciphertext
def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    plaintext = pad_text(plaintext)
    blocks = []
    while len(plaintext) > 0:
        # NOTE: not supposed to reuse AES objects (see docs)
        cipher = AES.new(key, AES.MODE_ECB)
        blocks.append(cipher.encrypt(plaintext[:16]))
        plaintext = plaintext[16:]

    return b"".join(blocks)


# Decrypt the ciphertext using ECB mode
# Return the plaintext
def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    blocks = []
    while len(ciphertext) > 0:
        cipher = AES.new(key, AES.MODE_ECB)
        blocks.append(cipher.decrypt(ciphertext[:16]))
        ciphertext = ciphertext[16:]

    return remove_padding(b"".join(blocks))


# Encrypt the plaintext using CBC mode
# Return the ciphertext
def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    plaintext = pad_text(plaintext)
    blocks = []
    while len(plaintext) > 0:
        curr_block = plaintext[:16]
        prev_block = iv if len(blocks) == 0 else blocks[-1]
        # XOR the current block with the previous block
        xor = int.from_bytes(prev_block) ^ int.from_bytes(curr_block)
        cipher = AES.new(key, AES.MODE_ECB)  # mode needs to be ECB
        encrypted_block = cipher.encrypt(xor.to_bytes(length=16))
        blocks.append(encrypted_block)
        plaintext = plaintext[16:]

    return b"".join(blocks)


# Decrypt the ciphertext using CBC mode
# Return the plaintext
def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher_blocks = []
    blocks = []
    while len(ciphertext) > 0:
        curr_block = ciphertext[:16]
        prev_block = iv if len(blocks) == 0 else cipher_blocks[-1]
        cipher_blocks.append(curr_block)
        cipher = AES.new(key, AES.MODE_ECB)  # mode needs to be ECB
        curr_block = cipher.decrypt(curr_block)
        # XOR the current block with the previous block
        xor = int.from_bytes(prev_block) ^ int.from_bytes(curr_block)
        blocks.append(xor.to_bytes(length=16))
        ciphertext = ciphertext[16:]

    return remove_padding(b"".join(blocks))


# Generate random bytes
def random_bytes(len: int) -> bytes:
    return os.urandom(len)


# Pad the text to be a multiple of 16 bytes
def pad_text(plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    return plaintext + bytes([pad] * pad)


# Remove the padding from the text
def remove_padding(plaintext: bytes) -> bytes:
    return plaintext[: -plaintext[-1]]


# Encrypt and decrypt the image using ECB and CBC modes
# Save the encrypted and decrypted images to new files
def main() -> None:
    key = b"1234567890123456"
    mode = "ecb"
    encrypt_image("cp-logo.bmp", mode, key)
    decrypt_image(f"encrypted_cp-logo_{mode}.bmp", mode, key)
    mode = "cbc"
    encrypt_image("cp-logo.bmp", mode, key)
    decrypt_image(f"encrypted_cp-logo_{mode}.bmp", mode, key)


if __name__ == "__main__":
    main()
