from dataclasses import dataclass

from pgp.crypto import RSAPublicKey


@dataclass
class Client:
    host: str
    port: int
    public_key: RSAPublicKey
    username: str

    def __hash__(self):
        return hash(f"{self.host}:{self.port}")
