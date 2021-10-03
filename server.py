from aiohttp import web
from common import *
import time
import base64
from cryptography import fernet
from aiohttp import web
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage


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

    def run_app(self):
        web.run_app(self.app)

    async def hello(self, request):
        return web.Response(text="Hello, world")

    async def echo(self, request):
        data = {'echo': await request.text()}
        return web.json_response(data)

    async def generate_session_key(self, request, open_key):
        session = await get_session(request)
        last_visit = session['last_visit'] if 'last_visit' in session else None
        session[OPEN_KEY] = f'my beautiful key + {open_key}'
        print('session key generated successfully')

    async def register(self, request):
        json = await request.json()
        print(json)
        # user_login, pwd, key
        self.users[json[LOGIN]] = {
            PASSWORD: json[PASSWORD],
            OPEN_KEY: json[OPEN_KEY],
        }
        print(f'user {json[LOGIN]} registered successfully')
        await self.generate_session_key(request, json[OPEN_KEY])
        return web.json_response(text='user registered successfully')

    async def login(self, request):
        pass

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
