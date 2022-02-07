# pylint: disable=missing-module-docstring, missing-class-docstring, missing-function-docstring

import base64

from Crypto.Cipher import AES

class AES_CBC_Cipher:

    def __init__(self, key: bytes) -> None:
        self.key = key

    @staticmethod
    def pad(s: bytes) -> bytes:
        return s + (AES.block_size - len(s) % AES.block_size) \
                   * bytes([AES.block_size - len(s) % AES.block_size])

    @staticmethod
    def unpad(s: bytes) -> bytes:
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, iv: bytes, raw: bytes) -> bytes:
        raw = self.pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc: bytes) -> bytes:
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:]))
