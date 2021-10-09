import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LOGIN = 'login'
PASSWORD = 'password'
OPEN_KEY = 'open_key'
SHARED_KEY = 'shared_key'
PRIVATE_KEY = 'private_key'
PUBLIC_KEY = 'public_key'
SHARED_KEY = 'shared_key'
SESSION_ID = 'session_id'
FILE_NAME = 'file_name'
CT = "ct"
IV = "iv"
KEY_EXPIRED = 'Session key was not added or expired: login again.'

BASE_KEY_DIR = os.path.dirname(os.path.abspath(__file__)) + '/keys/'


def encode_doc(text, shared_key, iv):
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    data = text.encode('ascii')
    ct = base64.b64encode(encryptor.update(data) + encryptor.finalize()).decode(
        'ascii')
    iv = base64.b64encode(iv).decode('ascii')
    return iv, ct


def decode_doc(ct, shared_key, iv):
    iv = base64.b64decode(iv.encode('ascii'))
    ct = base64.b64decode(ct.encode('ascii'))
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    ct = decryptor.update(ct) + cipher.decryptor().finalize()
    return ct
