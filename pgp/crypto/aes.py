from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Tuple


class AES:
    """
    Using 256-bit keys
    """

    @staticmethod
    def encrypt(plaintext: str | bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-CBC mode.
        Args:
            key (bytes): The AES key.
            plaintext (bytes or str): Plaintext data to encrypt.
            iv (bytes): Optional nonce (initialization vector); if not provided, a random one is used.

        Returns:
            tuple: (ciphertext, iv) where `iv` is the initialization vector used for encryption. Both are bytes
        """
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        if iv is None:
            iv = urandom(16)  # AES block size for IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, iv

    @staticmethod
    def decrypt(ciphertext: str | bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypts ciphertext using AES-CBC mode.

        Args:
            key (bytes): The AES key.
            ciphertext (bytes or str): Ciphertext data to decrypt.
            iv (bytes): Nonce (initialization vector) used during the encryption.

        Returns:
            bytes: The decrypted plaintext.
        """
        if not isinstance(ciphertext, bytes):
            plaintext = ciphertext.encode('utf-8')
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_bytes

    @staticmethod
    def generate_key() -> Tuple[bytes, bytes]:
        """
        Generate a random AES key of 256 bits and initialization vector of 128 bits
        """
        aes_key = urandom(32)
        aes_iv = urandom(16)
        return aes_key, aes_iv
