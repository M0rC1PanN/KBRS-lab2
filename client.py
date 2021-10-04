import base64
import json
import os
import uuid

import aiohttp
import asyncio

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from aiohttp_session import Session

CLIENT_FILES_DIR = os.path.dirname(os.path.abspath(__file__)) + '/client_docs/'


class SessionHandler:
    def __init__(self, url, session):
        self.url = url
        self.session = session
        self.shared_key = None
        self.session_id = str(uuid.uuid4())
        self.cookies = {
            SESSION_ID: self.session_id
        }

    def get_shared_key(self, iv):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=iv,
            iterations=100000,
        )
        return kdf.derive(self.shared_key)

    async def echo(self, data, data2='optional data'):
        echo_json = {
            'echo': data,
            'echo2': data2,
        }
        async with self.session.post(f'{self.url}/echo',
                                     json=echo_json) as resp:
            print(resp.status)
            print(await resp.text())

    async def register(self, user_login, pwd):
        register_json = {
            LOGIN: user_login,
            PASSWORD: pwd,
        }
        async with self.session.post(f'{self.url}/register',
                                     json=register_json,
                                     cookies=self.cookies) as resp:
            print(resp.status)
            print(await resp.text())

    async def login(self, user_login, pwd):
        client_private_key = ec.generate_private_key(ec.SECP384R1())
        client_public_key = client_private_key.public_key()
        client_public_key_decoded = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        login_json = {
            LOGIN: user_login,
            PASSWORD: pwd,
            OPEN_KEY: client_public_key_decoded,
        }
        async with self.session.post(f'{self.url}/login',
                                     json=login_json,
                                     cookies=self.cookies) as resp:
            print(resp.status)
            if resp.status != 200:
                print(await resp.text())
                return
            server_open_key = await resp.text()
            server_open_key = serialization \
                .load_pem_public_key(server_open_key.encode("utf-8"))
        shared_key = client_private_key.exchange(ec.ECDH(), server_open_key)
        self.shared_key = shared_key

    async def get_doc(self, file_name):
        get_doc_json = {FILE_NAME: file_name}
        async with self.session.post(f'{self.url}/get_doc',
                                     json=get_doc_json,
                                     cookies=self.cookies) as resp:
            if resp.status != 200:
                print(await resp.text())
                return
            data = json.loads(await resp.text())
            print(data)
            iv = base64.b64decode(data["iv"].encode('ascii'))
            shared_key = self.get_shared_key(iv)
            ct = decode_doc(data["ct"], shared_key, data["iv"])
            print(ct)

    async def add_doc(self, file_name):
        try:
            with open(CLIENT_FILES_DIR + file_name, 'r') as file:
                text = file.read()
                iv = os.urandom(16)
                shared_key = self.get_shared_key(iv)
                iv, ct = encode_doc(text, shared_key, iv)
                add_doc_json = {FILE_NAME: file_name, CT: ct, IV: iv}
                async with self.session.post(f'{self.url}/add_doc',
                                             json=add_doc_json,
                                             cookies=self.cookies) as resp:
                    print(await resp.text())
        except FileNotFoundError as ex:
            print(f"no such file: {ex}")

    async def update_doc(self, file_name):
        await self.add_doc(file_name)

    async def delete_doc(self, file_name):
        delete_doc_json = {FILE_NAME: file_name}
        async with self.session.post(f'{self.url}/delete_doc',
                                     json=delete_doc_json,
                                     cookies=self.cookies) as resp:
            print(resp.status)
            print(await resp.text())

    async def logout(self):
        async with self.session.post(f'{self.url}/logout',
                                     cookies=self.cookies) as resp:
            print(resp.status)
            if resp.status != 200:
                print(await resp.text())


async def main():
    async with aiohttp.ClientSession() as session:
        session_handler = SessionHandler('http://0.0.0.0:8080', session)
        while True:
            method, *args = input().split()
            try:
                await getattr(session_handler, method)(*args)
            except AttributeError as e:
                print(f"wrong function {e}")


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
