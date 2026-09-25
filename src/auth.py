"""認証。サーバ側セッション（Redis）。

セッション ID だけをクライアントに渡し、状態はサーバ側に置く。
失効はセッションを消すだけで、次のリクエストから効く。
"""

from __future__ import annotations

import os
import secrets
from typing import Protocol

SESSION_TTL_SECONDS = 14 * 24 * 60 * 60

_PREFIX = "session:"


class SessionError(Exception):
    """無効なセッション。理由は呼び出し側へ返さない。"""


class SessionStore(Protocol):
    def set(self, key: str, value: str, ex: int) -> None: ...
    def get(self, key: str) -> str | None: ...
    def delete(self, *keys: str) -> None: ...
    def scan_iter(self, match: str): ...


def redis_store() -> SessionStore:
    import redis

    url = os.environ.get("SESSION_REDIS_URL", "")
    if not url:
        raise RuntimeError("SESSION_REDIS_URL is not set")
    return redis.Redis.from_url(url, decode_responses=True)


def create_session(store: SessionStore, user_id: str) -> str:
    """ログイン成功時に呼ぶ。返したセッション ID を Cookie に入れる。"""
    session_id = secrets.token_urlsafe(32)
    store.set(f"{_PREFIX}{session_id}", user_id, ex=SESSION_TTL_SECONDS)
    return session_id


def resolve_session(store: SessionStore, session_id: str) -> str:
    """リクエストごとに呼ぶ。"""
    user_id = store.get(f"{_PREFIX}{session_id}")
    if not user_id:
        raise SessionError()
    return user_id


def revoke_session(store: SessionStore, session_id: str) -> None:
    store.delete(f"{_PREFIX}{session_id}")


def revoke_user(store: SessionStore, user_id: str) -> int:
    """そのユーザーの全セッションを消す。"""
    keys = [key for key in store.scan_iter(match=f"{_PREFIX}*") if store.get(key) == user_id]
    if keys:
        store.delete(*keys)
    return len(keys)
