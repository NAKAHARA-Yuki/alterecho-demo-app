"""認証。JWT ベース。

モバイルクライアントの追加を見込み、サーバ側にセッションストアを持たない
構成にする。アクセストークン15分、リフレッシュトークン14日。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 14

_ALGORITHM = "HS256"


class TokenError(Exception):
    """検証に失敗したトークン。理由は呼び出し側へ返さない。"""


def _secret() -> bytes:
    secret = os.environ.get("JWT_SIGNING_SECRET", "")
    if not secret:
        raise RuntimeError("JWT_SIGNING_SECRET is not set")
    return secret.encode("utf-8")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(signing_input: bytes) -> str:
    return _b64(hmac.new(_secret(), signing_input, hashlib.sha256).digest())


def issue_access_token(user_id: str, *, now: float | None = None) -> str:
    """アクセストークンを発行する。"""
    issued_at = int(now if now is not None else time.time())
    header = {"alg": _ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": user_id,
        "iat": issued_at,
        "exp": issued_at + ACCESS_TOKEN_TTL_MINUTES * 60,
    }
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    return f"{signing_input}.{_sign(signing_input.encode('ascii'))}"


def verify_access_token(token: str, *, now: float | None = None) -> str:
    """トークンを検証して user_id を返す。

    署名を先に見る。期限切れかどうかを署名の前に答えると、
    偽造したトークンでも有効期限の有無が分かってしまう。
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token")
    signing_input, signature = f"{parts[0]}.{parts[1]}", parts[2]
    if not hmac.compare_digest(_sign(signing_input.encode("ascii")), signature):
        raise TokenError("bad signature")
    payload = json.loads(_unb64(parts[1]))
    if int(payload.get("exp", 0)) <= int(now if now is not None else time.time()):
        raise TokenError("expired")
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenError("missing subject")
    return subject
