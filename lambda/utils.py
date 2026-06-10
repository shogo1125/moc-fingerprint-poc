"""
共通ユーティリティ
FIDO2/WebAuthn Lambda 関数で共有するヘルパー関数群
"""

import json
import os
import time
import uuid
import boto3
from boto3.dynamodb.conditions import Key

# DynamoDB リソース（Lambda コールドスタート時に一度だけ初期化）
_dynamodb = boto3.resource("dynamodb")

# テーブル名は環境変数から取得
CREDENTIALS_TABLE = os.environ["CREDENTIALS_TABLE"]
CHALLENGES_TABLE = os.environ["CHALLENGES_TABLE"]
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

# チャレンジの有効期限（秒）: 5分
CHALLENGE_TTL_SECONDS = 300


def get_credentials_table():
    """認証情報テーブルのリソースを返す"""
    return _dynamodb.Table(CREDENTIALS_TABLE)


def get_challenges_table():
    """チャレンジテーブルのリソースを返す"""
    return _dynamodb.Table(CHALLENGES_TABLE)


# -------------------------------------------------------
# HTTP レスポンス生成ヘルパー
# -------------------------------------------------------

def ok(body: dict) -> dict:
    """200 OK レスポンスを生成する"""
    return {
        "statusCode": 200,
        "headers": _cors_headers(),
        "body": json.dumps(body, ensure_ascii=False),
    }


def error(status: int, message: str) -> dict:
    """エラーレスポンスを生成する"""
    return {
        "statusCode": status,
        "headers": _cors_headers(),
        "body": json.dumps({"error": message}, ensure_ascii=False),
    }


def options_response() -> dict:
    """CORS プリフライトリクエスト（OPTIONS）への応答"""
    return {
        "statusCode": 200,
        "headers": _cors_headers(),
        "body": "",
    }


def _cors_headers() -> dict:
    """CORS ヘッダーを返す（すべてのレスポンスに付与）"""
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
    }


def get_event_header(event: dict, name: str) -> str:
    """API Gateway イベントからヘッダーを取得（大文字小文字を無視）"""
    headers = event.get("headers") or {}
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return ""


def get_expected_origin(event: dict) -> str | list[str]:
    """
    WebAuthn 検証用の期待オリジンを返す。
    リクエストの Origin が許可リストにあればそれを使う。
    """
    origin = get_event_header(event, "origin")
    allowed_origins = [
        "http://localhost:8080",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
    ]

    cf_origin = os.environ.get("ALLOWED_ORIGIN", "")
    if cf_origin and cf_origin != "*":
        allowed_origins.append(cf_origin)

    if origin in allowed_origins:
        return origin

    return allowed_origins


def as_bytes(value) -> bytes:
    """DynamoDB Binary / bytes を統一的に bytes に変換する"""
    if isinstance(value, bytes):
        return value
    if hasattr(value, "value"):
        return value.value
    return bytes(value)


# -------------------------------------------------------
# チャレンジ管理（DynamoDB）
# -------------------------------------------------------

def save_challenge(challenge: str, user_id: str) -> str:
    """
    チャレンジを DynamoDB に保存し、challenge_id を返す。
    TTL を設定して CHALLENGE_TTL_SECONDS 後に自動削除される。

    Args:
        challenge: WebAuthn チャレンジ（base64url 文字列）
        user_id: 関連するユーザー ID

    Returns:
        challenge_id: チャレンジを一意に識別する UUID
    """
    table = get_challenges_table()
    challenge_id = str(uuid.uuid4())
    expires_at = int(time.time()) + CHALLENGE_TTL_SECONDS

    table.put_item(Item={
        "challengeId": challenge_id,
        "challenge": challenge,
        "userId": user_id,
        "expiresAt": expires_at,  # DynamoDB TTL 属性
    })
    return challenge_id


def consume_challenge(challenge_id: str) -> dict | None:
    """
    チャレンジを DynamoDB から取得して削除（1回限り使用）。

    Args:
        challenge_id: save_challenge で返された UUID

    Returns:
        チャレンジ情報の dict（challenge, userId）、見つからなければ None
    """
    table = get_challenges_table()

    # チャレンジを取得して即削除（リプレイ攻撃防止）
    response = table.delete_item(
        Key={"challengeId": challenge_id},
        ReturnValues="ALL_OLD",
    )
    item = response.get("Attributes")
    if not item:
        return None

    # 期限切れチェック（TTL が効く前に手動でも確認）
    if int(time.time()) > item.get("expiresAt", 0):
        return None

    return item


# -------------------------------------------------------
# 認証情報管理（DynamoDB）
# -------------------------------------------------------

def save_credential(
    user_id: str,
    credential_id: str,
    public_key: bytes,
    sign_count: int,
    display_name: str,
) -> None:
    """
    登録済み公開鍵情報を DynamoDB に保存する。

    Args:
        user_id: ユーザーを識別する文字列（例: メールアドレス）
        credential_id: FIDO2 credential ID（base64url）
        public_key: COSE エンコードされた公開鍵（bytes）
        sign_count: 初期署名カウンター（リプレイ攻撃検出に使用）
        display_name: ユーザー表示名
    """
    table = get_credentials_table()
    table.put_item(Item={
        "userId": user_id,
        "credentialId": credential_id,
        # bytes は DynamoDB Binary として保存
        "publicKey": public_key,
        "signCount": sign_count,
        "displayName": display_name,
        "createdAt": int(time.time()),
    })


def get_credential_by_id(credential_id: str) -> dict | None:
    """
    credential_id で認証情報を検索する（GSI を使用）。

    Args:
        credential_id: FIDO2 credential ID（base64url）

    Returns:
        認証情報の dict、見つからなければ None
    """
    table = get_credentials_table()
    response = table.query(
        IndexName="credentialId-index",
        KeyConditionExpression=Key("credentialId").eq(credential_id),
        Limit=1,
    )
    items = response.get("Items", [])
    return items[0] if items else None


def update_sign_count(user_id: str, credential_id: str, new_count: int) -> None:
    """
    署名カウンターを更新する（認証成功後に必ず呼ぶ）。
    カウンターが増加していることの確認はカウンター取得後に行う。

    Args:
        user_id: ユーザー ID
        credential_id: FIDO2 credential ID
        new_count: 新しい署名カウンター値
    """
    table = get_credentials_table()
    table.update_item(
        Key={"userId": user_id, "credentialId": credential_id},
        UpdateExpression="SET signCount = :c",
        ExpressionAttributeValues={":c": new_count},
    )


def increment_auth_stats(user_id: str, credential_id: str, success: bool) -> None:
    """
    認証成功・失敗の回数を DynamoDB にアトミックに加算する。
    PoC での精度検証（FAR/FRR 計測）に使用する。

    Args:
        user_id: ユーザー ID
        credential_id: FIDO2 credential ID（base64url）
        success: True = 成功カウンター加算、False = 失敗カウンター加算
    """
    table = get_credentials_table()
    field = "authSuccessCount" if success else "authFailCount"
    try:
        table.update_item(
            Key={"userId": user_id, "credentialId": credential_id},
            UpdateExpression="ADD #f :one",
            ExpressionAttributeNames={"#f": field},
            ExpressionAttributeValues={":one": 1},
        )
    except Exception as exc:
        # カウンター更新失敗は認証フローを止めない（ベストエフォート）
        print(f"[WARN] stats 更新失敗: {exc}")


def get_credentials_for_user(user_id: str) -> list[dict]:
    """
    ユーザーが登録した全ての認証情報を返す。
    認証開始時にデバイス一覧を返すために使用。

    Args:
        user_id: ユーザー ID

    Returns:
        認証情報の list（各要素: credentialId, publicKey, signCount）
    """
    table = get_credentials_table()
    response = table.query(
        KeyConditionExpression=Key("userId").eq(user_id),
    )
    return response.get("Items", [])
