"""認証。JWT ベース。

モバイルクライアントの追加を見込み、サーバ側にセッションストアを持たない
構成にする。アクセストークン15分、リフレッシュトークン14日。
"""

ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 14


def issue_access_token(user_id: str) -> str:
    """アクセストークンを発行する（デモ用のスタブ）。"""
    raise NotImplementedError


def verify_access_token(token: str) -> str:
    """トークンを検証して user_id を返す（デモ用のスタブ）。"""
    raise NotImplementedError
