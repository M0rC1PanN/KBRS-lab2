import aiohttp
import asyncio
from common import *


class SessionHandler:
    def __init__(self, url, session):
        self.url = url
        self.session = session
        self.shared_key = None

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
                                     json=register_json) as resp:
            print(resp.status)
            print(await resp.text())


async def main():
    async with aiohttp.ClientSession() as session:
        session_handler = SessionHandler('http://0.0.0.0:8080', session)
        while True:
            method, *args = input().split()
            await getattr(session_handler, method)(*args)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
