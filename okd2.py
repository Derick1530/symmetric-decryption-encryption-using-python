import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
secret_key = base64.b64decode(
    # generated randomly once, kept secret
    "7Y/Ycbyw407VkBBKh7veNkpk9uBHg+h4YT+PTkcIcY8="
)


def fix_binary_data_length(binary_data):
    """
    Right padding of binary data with 0 bytes
    Fix "ValueError: The length of the provided data is not a multiple of the block length."
    """
    block_length = 16
    binary_data_length = len(binary_data)
    length_with_padding = (
        binary_data_length + (block_length - binary_data_length) % block_length
    )
    return binary_data.ljust(length_with_padding, "\0"), binary_data_length


def encrypt(binary_data):
    binary_data, binary_data_length = fix_binary_data_length(binary_data)
    iv = os.urandom(
        16
    )  # does not need to be secret, but must be unpredictable at encryption time

    # AES (Advanced Encryption Standard) is a block cipher standardized by NIST. AES is both fast, and cryptographically strong. It is a good default choice for encryption.
    # CBC (Cipher Block Chaining) is a mode of operation for block ciphers. It is considered cryptographically strong. (see https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC)
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(binary_data) + encryptor.finalize()
    stored_encrypted_data = "AES.MODE_CBC${iv}${binary_data_length}${encrypted_data})".format(
        iv=base64.b64encode(iv),
        binary_data_length=binary_data_length,
        encrypted_data=base64.b64encode(encrypted_data),
    )

    return stored_encrypted_data


def decrypt(stored_encrypted_data):
    algorithm, iv, binary_data_length, encrypted_data = stored_encrypted_data.split("$")
    assert algorithm == "AES.MODE_CBC"
    iv = base64.b64decode(iv)
    encrypted_data = base64.b64decode(encrypted_data)
    binary_data_length = int(binary_data_length)
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data[:binary_data_length]


if __name__ == "__main__":
    import json

    data = json.dumps(
        {u"type": u"example of json that could be symmetrically encrypted 😀 "}
    )
    stored_encrypted_data = encrypt(data.encode("utf-8"))
    decrypted_data = decrypt(stored_encrypted_data)
    print(json.loads(decrypted_data.decode("utf-8")))