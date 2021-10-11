from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common import *
import base64
from cryptography import fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from aiohttp import web
from aiohttp_session import setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import os
from pathlib import Path

BASE_FILES_DIR = os.path.dirname(os.path.abspath(__file__)) + '/docs/'

KEY_EXPIRED_JSON = web.json_response(
    text=KEY_EXPIRED,
    status=400)


class Server:
    @dataclass
    class Session:
        shared_key: bytes
        session_created: datetime
        files_folder: str

    def __init__(self):
        self.app = web.Application()

        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(self.app, EncryptedCookieStorage(secret_key))

        self.app.add_routes([
            web.post('/login', self.login),
            web.post('/logout', self.logout),
            web.post('/get_doc', self.get_doc),
            web.post('/add_doc', self.add_doc),
            web.post('/update_doc', self.update_doc),
            web.post('/delete_doc', self.delete_doc),
        ])
        self.sessions = {}
        self.expiration_interval_sec = 120

    def run_app(self):
        web.run_app(self.app)

    def check_session(self, request):
        session_id = request.cookies.get(SESSION_ID)
        if session_id not in self.sessions or \
                session_id not in self.sessions:
            return False
        sub_seconds_active = \
            (datetime.now() - self.sessions[
                session_id].session_created).total_seconds()
        print(f'active: {sub_seconds_active}')
        if sub_seconds_active > self.expiration_interval_sec:
            return False
        return True

    async def generate_session_key(self, request, open_key):
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        client_public_key = serialization.load_pem_public_key(
            open_key.encode("utf-8"))
        shared_key = private_key.exchange(ec.ECDH(), client_public_key)
        self.sessions[request.cookies[SESSION_ID]] = Server.Session(
            shared_key,
            datetime.now(),
            f'client_{open_key[27:40]}'
        )

        print(f'session key for session {request.cookies[SESSION_ID]} '
              f'generated successfully')
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def get_shared_key(self, request, iv):
        session_id = request.cookies[SESSION_ID]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=iv,
            iterations=100000,
        )
        return kdf.derive(self.sessions[session_id].shared_key)

    def get_file_path(self, request, file_name):
        folder_name = self.sessions[request.cookies[SESSION_ID]].files_folder
        return f'{BASE_FILES_DIR}{folder_name}/{file_name}'

    def get_dir_path(self, request):
        folder_name = self.sessions[request.cookies[SESSION_ID]].files_folder
        return f'{BASE_FILES_DIR}{folder_name}'

    async def login(self, request):
        json = await request.json()

        server_public_key_decoded = await self \
            .generate_session_key(request, json[OPEN_KEY])
        return web.json_response(text=server_public_key_decoded)

    async def logout(self, request):
        if not self.check_session(request):
            return KEY_EXPIRED_JSON
        session_id = request.cookies[SESSION_ID]
        del self.sessions[session_id]
        return web.json_response(status=200)

    async def get_doc(self, request):
        if not self.check_session(request):
            return KEY_EXPIRED_JSON
        json = await request.json()
        file_name = json[FILE_NAME]

        try:
            with open(self.get_file_path(request, file_name), 'r') as file:
                iv = os.urandom(16)
                shared_key = self.get_shared_key(request, iv)
                text = file.read()
                iv, ct = encode_doc(text, shared_key, iv)
                return web.json_response({"iv": iv, "ct": ct})
        except FileNotFoundError as ex:
            return web.json_response(text=f"no such file: {ex}", status=404)

    async def add_doc(self, request):
        if not self.check_session(request):
            return KEY_EXPIRED_JSON
        json = await request.json()
        file_name = json[FILE_NAME]
        iv = json[IV]
        ct = json[CT]
        text = decode_doc(ct, self.get_shared_key(request, base64.b64decode(
            iv.encode('ascii'))), iv)
        Path(self.get_dir_path(request)).mkdir(exist_ok=True)
        file_path = self.get_file_path(request, file_name)
        if os.path.isfile(file_path):
            return web.json_response(text="file already exists", status=409)
        with open(file_path, "wb") as f:
            f.write(text)
            print(text)
        return web.json_response(text="file added")

    async def update_doc(self, request):
        if not self.check_session(request):
            return KEY_EXPIRED_JSON
        json = await request.json()
        file_name = json[FILE_NAME]
        iv = json[IV]
        ct = json[CT]
        text = decode_doc(ct, self.get_shared_key(request, base64.b64decode(
            iv.encode('ascii'))), iv)
        if not os.path.isfile(self.get_file_path(request, file_name)):
            return web.json_response(text="file not found", status=404)
        with open(self.get_file_path(request, file_name), "wb") as f:
            f.write(text)
            print(text)
        return web.json_response(text="file updated")

    async def delete_doc(self, request):
        if not self.check_session(request):
            return KEY_EXPIRED_JSON
        json = await request.json()
        file_name = json[FILE_NAME]
        try:
            os.remove(self.get_file_path(request, file_name))
            return web.json_response(text="file removed")
        except OSError as e:
            return web.json_response(text=f"file not found: {e}", status=404)


if __name__ == '__main__':
    server_app = Server()
    server_app.run_app()
