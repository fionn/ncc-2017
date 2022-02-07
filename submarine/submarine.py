#!/usr/bin/env python3
# pylint: disable=missing-module-docstring, missing-class-docstring, missing-function-docstring

from typing import Optional

from Crypto import Random

from aes_cbc_cipher import AES_CBC_Cipher

SECRET_KEY = b"abcdefghijklmnop" # not the real one =)

def validate_credentials(user: str, password: str) -> bool:
    return user == "qwerty" and password == "asdf"

def login(user: str, password: str) -> Optional[bytes]:

    if not validate_credentials(user, password):
        return None

    cipher = AES_CBC_Cipher(SECRET_KEY)

    IV = Random.new().read(16)
    return cipher.encrypt(IV, user.encode())

def main() -> None:

    has_token = input("Do you have a token? (y/n)\n")

    if has_token == "y":
        ciphertext = input("token?\n").encode()

        cipher = AES_CBC_Cipher(SECRET_KEY)
        user = cipher.decrypt(ciphertext).decode()

        print(f"You are logged in as {user}")
    else:
        user = input("user?\n")
        password = input("password?\n")

        token = login(user, password)

        if not token:
            print("Wrong credentials")
        else:
            print("Success. here's your token:")
            print(token.decode())

if __name__ == "__main__":
    main()
