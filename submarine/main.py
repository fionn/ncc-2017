#!/usr/bin/env python3
"""Find a token to let us log in as david"""

import base64

from aes_cbc_cipher import AES_CBC_Cipher
import submarine


def strxor(a: bytes, b: bytes) -> bytes:
    """Element-wise xor"""
    return bytes([i ^ j for i, j in zip(a, b, strict=True)])


def attack(token_map: dict[str, str], target_user: str) -> bytes:
    """Forge a token"""
    user, b64_token = token_map.popitem()
    token = base64.b64decode(b64_token)

    m = AES_CBC_Cipher.pad(user.encode())
    iv = token[:16]
    c = token[16:]

    # In CBC, we have
    #   D_k(c) xor iv = m,
    # so we can generate arbitrary m' with
    #   D_k(c) xor iv' = m'
    # since the iv is attacker controlled. Construct iv' as
    #   iv' = m' xor D_k(c)
    #       = m' xor m xor iv.
    # The token for message m, t_m = iv + c, can be transformed into
    # a token for message m' by swapping iv for iv', so
    #   t_m' = iv' + c.

    m_prime = AES_CBC_Cipher.pad(target_user.encode())
    iv_prime = strxor(strxor(m, iv), m_prime)
    token_prime = iv_prime + c

    # Match what submarine.login returns.
    return base64.b64encode(token_prime)


def main() -> None:
    """Entry point"""
    # Generate a token using the fake key, so we can test it.
    user = "qwerty"
    token = submarine.login(user, "asdf")

    # Sanity check.
    cipher = AES_CBC_Cipher(submarine.SECRET_KEY)
    assert user == cipher.decrypt(token).decode()

    # Forge the token against the fake key.
    target_user = "fionn"
    token_prime = attack({user: token.decode()}, target_user)
    assert target_user == cipher.decrypt(token_prime).decode()

    # Real attack against the supplied token.
    token_map = {"qwerty": "6obi67W57jYVxJyh3vyTp7l31dHghJSWP117i+wqTa4="}
    token_prime = attack(token_map, target_user="david")
    print(token_prime.decode())


if __name__ == "__main__":
    main()
