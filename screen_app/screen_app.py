#!/usr/bin/env python3
"""MitM the screen app"""

from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Random.random import randrange
from Crypto.Util.Padding import pad, unpad


def strxor(a: bytes, b: bytes) -> bytes:
    """Element-wise xor"""
    return bytes([i ^ j for i, j in zip(a, b, strict=True)])


class DHPeer:
    """Class to encapsulate DH logic"""

    def __init__(self, p: int, g: int) -> None:
        self.p = p
        self.g = g
        self._a = randrange(p)

    def public_key(self) -> int:
        """DH public key"""
        return pow(self.g, self._a, self.p)

    def session_key(self, B: int) -> int:
        """Shared session key"""
        return pow(B, self._a, self.p)


class Server:
    """Aircraft screen"""

    def __init__(self) -> None:
        self.code = randrange(10000)
        self.k = sha256(self.code.to_bytes(2, "big")).digest()
        self.dh: DHPeer = None
        self.session_key: bytes = None

    def init_dh(self, p: int, g: int) -> None:
        """Start the DH key exchange"""
        self.dh = DHPeer(p, g)

    def gen_session_key(self, B: int) -> None:
        """Session key derived from the DH session key and the pairing code"""
        self.session_key = strxor(self.dh.session_key(B).to_bytes(32, "big"), self.k)

    def hello(self) -> bytes:
        """Assume this is the client hello of a well known protocol"""
        cipher = AES.new(self.session_key, AES.MODE_ECB)
        return cipher.encrypt(pad(b"hello", cipher.block_size))  # type: ignore


class Client:
    """Passenger phone"""

    def __init__(self, code: int) -> None:
        self.k = sha256(code.to_bytes(2, "big")).digest()
        self.dh: DHPeer = None
        self.session_key: bytes = None

    def init_dh(self, p: int, g: int) -> None:
        """Start the DH key exchange"""
        self.dh = DHPeer(p, g)

    def gen_session_key(self, B: int) -> None:
        """Session key derived from the DH session key and the pairing code"""
        self.session_key = strxor(self.dh.session_key(B).to_bytes(32, "big"), self.k)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt whatever we're sent using the session key"""
        cipher = AES.new(self.session_key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), cipher.block_size)  # type: ignore


class MitM:
    """Attack the pairing protocol"""

    def __init__(self) -> None:
        self.dh_server: DHPeer = None
        self.dh_client: DHPeer = None

    def code(self, ciphertext: bytes, dh_public_key: int) -> int:
        """Brute force decrypt the known protocol message"""
        dh_session_key = self.dh_server.session_key(dh_public_key).to_bytes(32, "big")
        for code in range(10000):
            k = sha256(code.to_bytes(2, "big")).digest()
            session_key = strxor(dh_session_key, k)
            cipher = AES.new(session_key, AES.MODE_ECB)
            try:
                message = unpad(cipher.decrypt(ciphertext), cipher.block_size)  # type: ignore
                if message == b"hello":
                    return code
            except ValueError:
                continue
        raise RuntimeError("Failed to find the code")

    def session_keys(self, code: int, server_public_key: int,
                                      client_public_key: int) -> dict[str, bytes]:
        """Find the session keys used by the two peers"""
        k = sha256(code.to_bytes(2, "big")).digest()
        server_dh_session_key = self.dh_server.session_key(server_public_key).to_bytes(32, "big")
        client_dh_session_key = self.dh_client.session_key(client_public_key).to_bytes(32, "big")

        return {"server": strxor(server_dh_session_key, k),
                "client": strxor(client_dh_session_key, k)}


def protocol() -> None:
    """Sanity check the protocol"""
    server = Server()
    client = Client(server.code)
    assert server.k == client.k

    # Agree on DH parameters
    p, g = 37, 5
    server.init_dh(p, g)
    client.init_dh(p, g)

    # Generate session key
    server.gen_session_key(client.dh.public_key())
    client.gen_session_key(server.dh.public_key())

    assert server.session_key == client.session_key
    assert client.decrypt(server.hello()) == b"hello"


def attack() -> int:
    """MitM the DH exchange and brute force the session key"""
    server = Server()
    client = Client(server.code)
    mallory = MitM()
    assert server.k == client.k

    # Server and client agree on DH parameters
    p, g = 37, 5
    server.init_dh(p, g)
    client.init_dh(p, g)

    # MitM the DH exchange, use the same parameters for simplicity
    mallory.dh_server = DHPeer(p, g)
    mallory.dh_client = DHPeer(p, g)

    # Generate session key
    server.gen_session_key(mallory.dh_server.public_key())
    client.gen_session_key(mallory.dh_client.public_key())

    # Intercept server hello and find the session key
    code = mallory.code(server.hello(), server.dh.public_key())
    assert server.code == code

    session_keys = mallory.session_keys(code, server.dh.public_key(),
                                              client.dh.public_key())
    assert server.session_key == session_keys["server"]
    assert client.session_key == session_keys["client"]

    return code


def main() -> None:
    """Entry point"""
    protocol()
    code = attack()
    print(code)


if __name__ == "__main__":
    main()
