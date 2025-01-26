import struct
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from .compression import Compression
from .aes import AES
from .rsa import RSA


class OpenPGP:
    @staticmethod
    def compose_message(message: str, receiver_public_key: RSAPublicKey, sender_private_key: RSAPrivateKey) -> bytes:
        # Generate session key for each message
        session_aes_key, session_aes_iv = AES.generate_key()

        # Compress message
        compressed_message = Compression.compress(message)

        # Encrypt message using session key
        encrypted_message, _ = AES.encrypt(compressed_message, session_aes_key, session_aes_iv)

        # Encrypt own session key with the receiver public key
        encrypted_aes_key = RSA.encrypt(session_aes_key, receiver_public_key)
        encrypted_aes_iv = RSA.encrypt(session_aes_iv, receiver_public_key)

        # Sign the message using own RSA private key
        signature = RSA.sign(compressed_message, sender_private_key)

        # Compose final message
        encrypted_message_len = struct.pack(">I", len(encrypted_message))
        encrypted_aes_key_len = struct.pack(">I", len(encrypted_aes_key))
        encrypted_aes_iv_len = struct.pack(">I", len(encrypted_aes_iv))
        signature_len = struct.pack(">I", len(signature))

        print("BEGIN")
        print(encrypted_message_len)
        print(encrypted_aes_key_len)
        print(encrypted_aes_iv_len)
        print(signature_len)
        print(encrypted_message)
        print(encrypted_aes_key)
        print(encrypted_aes_iv)
        print(signature)
        print("END")

        result = bytearray()
        result += encrypted_message_len
        result += encrypted_aes_key_len
        result += encrypted_aes_iv_len
        result += signature_len
        result += encrypted_message
        result += encrypted_aes_key
        result += encrypted_aes_iv
        result += signature

        return bytes(result)

    @staticmethod
    def decompose_message(message: bytes, receiver_private_key: RSAPrivateKey, sender_public_key: RSAPublicKey) -> str:
        # Obtain encrypted message, session key and signature
        encrypted_message_len = struct.unpack(">I", message[0:4])[0]
        encrypted_aes_key_len = struct.unpack(">I", message[4:8])[0]
        encrypted_aes_iv_len = struct.unpack(">I", message[8:12])[0]
        signature_len = struct.unpack(">I", message[12:16])[0]

        message = message[16:]

        encrypted_message = message[0:encrypted_message_len]
        message = message[encrypted_message_len:]

        encrypted_aes_key = message[0:encrypted_aes_key_len]
        message = message[encrypted_aes_key_len:]

        encrypted_aes_iv = message[0:encrypted_aes_iv_len]
        message = message[encrypted_aes_iv_len:]

        signature = message[0:signature_len]

        print("BEGIN")
        print(encrypted_message_len)
        print(encrypted_aes_key_len)
        print(encrypted_aes_iv_len)
        print(signature_len)
        print(encrypted_message)
        print(encrypted_aes_key)
        print(encrypted_aes_iv)
        print(signature)
        print("END")

        # Decrypt session key using own RSA private key
        session_aes_key = RSA.decrypt(encrypted_aes_key, receiver_private_key)
        session_aes_iv = RSA.decrypt(encrypted_aes_iv, receiver_private_key)

        # Decrypt the message with the decrypted key
        compressed_message = AES.decrypt(encrypted_message, session_aes_key, session_aes_iv)

        # Verify signature
        RSA.verify(compressed_message, signature, sender_public_key)

        # Decompress message
        result = Compression.decompress(compressed_message)

        return result
