#!/usr/bin/env python3
"""One-time interactive Telegram login to create /data/telegram.session.
Run inside the worker container: docker compose run --rm worker python scripts/telegram_login.py"""
import asyncio
import os

from telethon import TelegramClient  # type: ignore


async def main():
    c = TelegramClient("/data/telegram.session", int(os.environ["TELEGRAM_API_ID"]), os.environ["TELEGRAM_API_HASH"])
    await c.start()
    me = await c.get_me()
    print("authorized as", me.username or me.id)
    await c.disconnect()


asyncio.run(main())
