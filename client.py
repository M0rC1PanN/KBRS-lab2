import aiohttp
import asyncio
from common import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class SessionHandler:
    def __init__(self, url, session):
        self.url = url
        self.session = session

    async def echo(self, data, data2='optional data'):
        echo_json = {
            'echo': data,
            'echo2': data2,
        }
        async with self.session.post(f'{self.url}/echo', json=echo_json) as resp:
            print(resp.status)
            print(await resp.text())

    async def register(self, user_login, pwd, open_key):
        register_json = {
            LOGIN: user_login,
            PASSWORD: pwd,
            OPEN_KEY: open_key
        }
        async with self.session.post(f'{self.url}/register', json=register_json) as resp:
            print(resp.status)
            print(await resp.text())

    async def login(self, user_login, pwd):
        client_private_key = ec.generate_private_key(ec.SECP384R1())
        client_public_key = client_private_key.public_key()
        register_json = {
            LOGIN: user_login,
            PASSWORD: pwd,
            OPEN_KEY: client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
        }
        async with self.session.post(f'{self.url}/login', json=register_json) as resp:
            print(resp.status)
            server_open_key = await resp.text()
            server_open_key = serialization.load_pem_public_key(server_open_key.encode("utf-8"))
        shared_key = client_private_key.exchange(ec.ECDH(), server_open_key)
        self.shared_key = shared_key


async def main():
    async with aiohttp.ClientSession() as session:
        session_handler = SessionHandler('http://0.0.0.0:8080', session)
        while True:
            method, *args = input().split()
            await getattr(session_handler, method)(*args)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
