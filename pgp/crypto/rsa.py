from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from typing import Tuple


class RSA:
    @staticmethod
    def _encrypt_block(block: bytes, public_key: RSAPublicKey) -> bytes:
        plaintext_int = int.from_bytes(block, byteorder='big')
        encrypted_numerical_block = pow(plaintext_int, public_key.public_numbers().e, public_key.public_numbers().n)
        encrypted_block = encrypted_numerical_block.to_bytes((encrypted_numerical_block.bit_length() + 7) // 8, byteorder='big')
        return encrypted_block

    @staticmethod
    def _decrypt_block(block: bytes, private_key: RSAPrivateKey) -> bytes:
        ciphertext_int = int.from_bytes(block, byteorder='big')
        decrypted_numerical_block = pow(ciphertext_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
        decrypted_block = decrypted_numerical_block.to_bytes((decrypted_numerical_block.bit_length() + 7) // 8, byteorder='big')
        return decrypted_block

    @staticmethod
    def encrypt(plaintext: str | bytes, public_key: RSAPublicKey) -> bytes:
        """

        Args:
            plaintext:
            public_key:

        Returns:
            bytes: the ciphertext
        """
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        blocks = [plaintext[i:i + 256] for i in range(0, len(plaintext), 256)]

        encrypted_blocks = [RSA._encrypt_block(block, public_key) for block in blocks]
        ciphertext = b''.join(encrypted_blocks)

        return ciphertext

    @staticmethod
    def decrypt(ciphertext: str | bytes, private_key: RSAPrivateKey) -> bytes:
        """

        Args:
            ciphertext:
            private_key:

        Returns:
            bytes: the decoded plaintext
        """
        if not isinstance(ciphertext, bytes):
            ciphertext = ciphertext.encode('utf-8')

        blocks = [ciphertext[i:i + 256] for i in range(0, len(ciphertext), 256)]

        decrypted_blocks = [RSA._decrypt_block(block, private_key) for block in blocks]
        plaintext = b''.join(decrypted_blocks)

        return plaintext


    @staticmethod
    def sign(message: str | bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Args:
            message:
            private_key:

        Returns:
            bytes: the signature
        """
        if not isinstance(message, bytes):
            message = message.encode('utf-8')
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify(message: str | bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
        """

        Args:
            message:
            signature:
            public_key:

        Returns:
            boolean: True if message is valid, False otherwise or if errors are encountered
        """
        if not isinstance(message, bytes):
            message = message.encode('utf-8')
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Verification successful")
            return True
        except Exception as e:
            print("Verification failed:", e)
            return False

    @staticmethod
    def generate_keys() -> Tuple[RSAPrivateKey, RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(key: RSAPublicKey) -> bytes:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(data: bytes) -> RSAPublicKey:
        return serialization.load_pem_public_key(data)

    @staticmethod
    def serialize_private_key(key: RSAPrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def deserialize_private_key(data: bytes) -> RSAPrivateKey:
        return serialization.load_pem_private_key(data, password=None)
