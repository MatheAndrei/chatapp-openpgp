import zlib


class Compression:
    @staticmethod
    def compress(message: str) -> bytes:
        """
               Compresses a given string into a compressed byte array using zlib.

               Args:
                   message (str): The input string to be compressed.

               Returns:
                   bytes: The compressed byte representation of the input string.
               """
        return zlib.compress(message.encode('utf-8'))

    @staticmethod
    def decompress(compressed_message: bytes) -> str:
        """
                Decompresses a given compressed byte array back into a string using zlib.

                Args:
                    compressed_message (bytes): The compressed byte array to be decompressed.

                Returns:
                    str: The decompressed string.
                """
        return zlib.decompress(compressed_message).decode('utf-8')
