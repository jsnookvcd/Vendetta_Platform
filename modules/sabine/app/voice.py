"""SABINE's spoken voice.

Text she has already written (an answer, the daily summary, her line on the
board) is rendered to audio by the configured provider and cached by content
hash, so the same sentence is never rendered twice and nothing she says aloud
differs from what is in the ledger.

Providers:
- browser: no server rendering; the page uses the viewer's own speech synthesis.
  The default, costs nothing, and no text leaves the host.
- elevenlabs: a chosen voice id, rendered through their API.
- azure: a chosen neural voice, rendered through Azure Speech.

Listening (push to talk on the Ask page) always runs in the browser; the
transcript goes to the same Ask endpoint as typed text.
"""
from __future__ import annotations

import hashlib
import logging

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .db import Speech

log = logging.getLogger(__name__)

_TRANSPORT: httpx.BaseTransport | None = None  # tests inject a MockTransport


def set_transport(t: httpx.BaseTransport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = t


def provider() -> str:
    p = (settings.tts_provider or "browser").lower()
    if p == "elevenlabs" and not (settings.elevenlabs_api_key and settings.elevenlabs_voice_id):
        return "browser"
    if p == "azure" and not (settings.azure_speech_key and settings.azure_speech_region):
        return "browser"
    return p if p in ("browser", "elevenlabs", "azure") else "browser"


def voice_label() -> str:
    p = provider()
    if p == "elevenlabs":
        return f"ElevenLabs voice {settings.elevenlabs_voice_id[:8]}"
    if p == "azure":
        return f"Azure {settings.azure_speech_voice}"
    return "browser speech synthesis"


def _key(text: str) -> str:
    p = provider()
    voice = settings.elevenlabs_voice_id if p == "elevenlabs" else settings.azure_speech_voice if p == "azure" else ""
    return hashlib.sha256(f"{p}|{voice}|{text}".encode()).hexdigest()


def _render_elevenlabs(text: str) -> tuple[bytes, str]:
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{settings.elevenlabs_voice_id}"
    with httpx.Client(timeout=60.0, transport=_TRANSPORT) as http:
        r = http.post(url, headers={"xi-api-key": settings.elevenlabs_api_key, "accept": "audio/mpeg"},
                      json={"text": text, "model_id": settings.elevenlabs_model,
                            "voice_settings": {"stability": 0.45, "similarity_boost": 0.8, "style": 0.35}})
    r.raise_for_status()
    return r.content, "audio/mpeg"


def _azure_body(safe: str) -> str:
    """Dragon HD voices set their own pacing and reject prosody tuning; the classic
    neural voices take a slight slow-down so she sounds unhurried."""
    if "dragonhd" in settings.azure_speech_voice.lower():
        return safe
    return f"<prosody rate='-3%' pitch='-1%'>{safe}</prosody>"


def _render_azure(text: str) -> tuple[bytes, str]:
    url = f"https://{settings.azure_speech_region}.tts.speech.microsoft.com/cognitiveservices/v1"
    safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    ssml = f"<speak version='1.0' xml:lang='en-US'><voice name='{settings.azure_speech_voice}'>{_azure_body(safe)}</voice></speak>"
    with httpx.Client(timeout=60.0, transport=_TRANSPORT) as http:
        r = http.post(url, content=ssml.encode(), headers={
            "Ocp-Apim-Subscription-Key": settings.azure_speech_key, "Content-Type": "application/ssml+xml",
            "X-Microsoft-OutputFormat": "audio-24khz-96kbitrate-mono-mp3", "User-Agent": "sabine"})
    r.raise_for_status()
    return r.content, "audio/mpeg"


def speak(db: Session, text: str) -> Speech | None:
    """Render (or fetch from cache) audio for text. Returns None for the browser
    provider, which renders client-side."""
    text = (text or "").strip()[:4000]
    if not text or provider() == "browser":
        return None
    key = _key(text)
    row = db.get(Speech, key)
    if row:
        return row
    try:
        data, mime = _render_elevenlabs(text) if provider() == "elevenlabs" else _render_azure(text)
    except httpx.HTTPError as e:
        log.warning("voice: %s render failed: %s", provider(), type(e).__name__)
        return None
    row = Speech(id=key, provider=provider(), mime=mime, text=text, data=data)
    db.add(row)
    db.commit()
    return row
