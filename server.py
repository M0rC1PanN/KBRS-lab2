import uuid

from aiohttp import web
from common import *
import base64
from cryptography import fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from aiohttp import web
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from typing import Callable


class Server:
    def __init__(self):
        self.app = web.Application()

        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(self.app, EncryptedCookieStorage(secret_key))

        self.app.add_routes([
            web.get('/', self.hello),
            web.post('/echo', self.echo),
            web.post('/register', self.register),
            web.post('/login', self.login),
            web.post('/logout', self.logout),
            web.post('/get_doc', self.get_doc),
            web.post('/add_doc', self.add_doc),
            web.post('/update_doc', self.update_doc),
            web.post('/delete_doc', self.delete_doc),
        ])
        self.users = {}
        self.shared_keys = {}

    def run_app(self):
        web.run_app(self.app)

    async def hello(self, request):
        return web.Response(text="Hello, world")

    async def echo(self, request):
        data = {'echo': await request.text()}
        return web.json_response(data)

    async def generate_session_key(self, request, open_key):
        session = await get_session(request)
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        client_public_key = serialization.load_pem_public_key(
            open_key.encode("utf-8"))
        shared_key = private_key.exchange(ec.ECDH(), client_public_key)
        if SESSION_ID not in session:
            session[SESSION_ID] = str(uuid.uuid4())
        print(session[SESSION_ID])
        self.shared_keys[session[SESSION_ID]] = shared_key

        # TODO: add key expiration
        print(f'session key for session {session.identity} '
              f'generated successfully')
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    async def register(self, request):
        json = await request.json()
        print(json)
        self.users[json[LOGIN]] = json[PASSWORD]
        print(f'user {json[LOGIN]} registered successfully')
        return web.json_response(text='user registered successfully')

    async def login(self, request):
        json = await request.json()
        print(json)
        user_pwd = self.users[json[LOGIN]]
        if user_pwd != json[PASSWORD]:
            return web.json_response(text='wrong password', status=404)

        server_public_key_decoded = await self \
            .generate_session_key(request,  json[OPEN_KEY])
        return web.json_response(text=server_public_key_decoded)

    async def logout(self, request):
        pass

    async def get_doc(self, request):
        pass

    async def add_doc(self, request):
        pass

    async def update_doc(self, request):
        pass

    async def delete_doc(self, request):
        pass


if __name__ == '__main__':
    server_app = Server()
    server_app.run_app()
