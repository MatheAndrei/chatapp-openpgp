from pgp.crypto.aes import AES
from pgp.crypto.compression import Compression
from pgp.crypto.rsa import RSA


sender_private_key, sender_public_key = RSA.generate_keys()
receiver_private_key, receiver_public_key = RSA.generate_keys()

while True:
    message =  input("Scrie mesajul: ")

    print("SENDER Outputs")

    # Generate session key for each message
    session_aes_key, session_aes_iv = AES.generate_key()
    print("Session key: ", len(session_aes_key), session_aes_key)
    print("Session iv: ", len((session_aes_iv)), session_aes_iv)

    # Compress message
    compressed_message_bytes = Compression.compress(message)
    print("Compressed message: ", compressed_message_bytes)

    # Encrypt message using session key
    encrypted_message_bytes, _ = AES.encrypt(compressed_message_bytes, session_aes_key, session_aes_iv)
    print("Compressed encrypted message: ", encrypted_message_bytes)

    # Request receiver public key
    print("Received RSA public key: ", receiver_public_key)

    # Encrypt own session key with the receiver public key
    encrypted_aes_key, encrypted_aes_iv = RSA.encrypt(session_aes_key, receiver_public_key), RSA.encrypt(session_aes_iv, receiver_public_key)
    print("Encrypted session key: ", len(encrypted_aes_key), encrypted_aes_key)
    print("Encrypted session iv: ", len(encrypted_aes_iv), encrypted_aes_iv)

    # Sign the message using own RSA private key
    signature = RSA.sign(compressed_message_bytes, sender_private_key)
    print("Signature: ", signature)

    print("\n\nRECEIVER Outputs")

    # Decrypt session key using own RSA private key
    decrypted_session_aes_key, decrypted_session_aes_iv = RSA.decrypt(encrypted_aes_key, receiver_private_key), RSA.decrypt(encrypted_aes_iv, receiver_private_key)
    print("Decrypted session key: ", decrypted_session_aes_key)
    print("Decrypted session iv: ", decrypted_session_aes_iv)

    # Decrypt the message with the decrypted key
    decrypted_compressed_received_message = AES.decrypt(encrypted_message_bytes, decrypted_session_aes_key, decrypted_session_aes_iv)
    print("Decrypted compressed message: ", decrypted_compressed_received_message)

    # Verify signature
    print(RSA.verify(decrypted_compressed_received_message, signature, sender_public_key))

    # Decompress message
    decompressed_message = Compression.decompress(compressed_message_bytes)
    print(decompressed_message)






