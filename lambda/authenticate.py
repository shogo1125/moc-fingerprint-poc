"""
FIDO2/WebAuthn 認証ハンドラ
MoC指紋認証 PoC — Relying Party（認証フェーズ）

エンドポイント:
  POST /auth/begin    → チャレンジ発行（ログイン要求）
  POST /auth/complete → 署名検証（MoCリーダーが生成したデジタル署名）
"""

import json
import os
import time

import webauthn
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.structs import (
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

from utils import (
    ok,
    error,
    options_response,
    save_challenge,
    consume_challenge,
    get_credential_by_id,
    get_credentials_for_user,
    update_sign_count,
    increment_auth_stats,
    get_expected_origin,
    as_bytes,
)

# Relying Party 設定（環境変数から取得）
RP_ID = os.environ["RP_ID"]


# -------------------------------------------------------
# POST /auth/begin
# -------------------------------------------------------
def begin_handler(event: dict, context) -> dict:
    """
    認証チャレンジを発行する。

    リクエスト Body:
        {
            "userId": "user@example.com"
        }

    レスポンス:
        WebAuthn PublicKeyCredentialRequestOptions（JSON）
        + challengeId
    """
    if event.get("httpMethod") == "OPTIONS":
        return options_response()

    try:
        body = json.loads(event.get("body") or "{}")
        user_id: str = body["userId"]
    except (KeyError, json.JSONDecodeError):
        return error(400, "userId は必須です")

    # ユーザーの登録済み credential を取得
    credentials = get_credentials_for_user(user_id)
    if not credentials:
        return error(404, "このユーザーは登録されていません。先に登録してください。")

    # 登録済みデバイスの credential リスト（allow_credentials）
    # MoCリーダーはここに含まれるデバイスのみ署名を生成できる
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credentialId"]))
        for c in credentials
    ]

    # py_webauthn で認証チャレンジを生成
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        # ユーザー検証必須: 指紋照合成功時のみ署名が生成される
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,  # 60秒
    )

    # チャレンジを DynamoDB に保存
    challenge_id = save_challenge(
        challenge=bytes_to_base64url(options.challenge),
        user_id=user_id,
    )

    options_json = webauthn.options_to_json(options)
    options_dict = json.loads(options_json)
    options_dict["challengeId"] = challenge_id

    return ok(options_dict)


# -------------------------------------------------------
# POST /auth/complete
# -------------------------------------------------------
def complete_handler(event: dict, context) -> dict:
    """
    MoCリーダーが生成したデジタル署名を検証してログインを許可する。

    フロー（MoC方式）:
      1. ユーザーがMoCリーダーに指を置く
      2. チップ内で指紋照合（生体データは外に出ない）
      3. 照合成功時のみ、チップ内の秘密鍵でチャレンジに署名
      4. 署名（credential）がブラウザ経由でここに届く
      5. DynamoDB の公開鍵で署名を検証する

    リクエスト Body:
        {
            "challengeId": "...",
            "userId":      "...",
            "credential":  { ... }  // navigator.credentials.get() の結果
        }

    レスポンス:
        {"ok": true, "userId": "...", "message": "認証成功"}
    """
    if event.get("httpMethod") == "OPTIONS":
        return options_response()

    try:
        body = json.loads(event.get("body") or "{}")
        challenge_id: str = body["challengeId"]
        user_id: str = body["userId"]
        credential_data: dict = body["credential"]
    except (KeyError, json.JSONDecodeError):
        return error(400, "challengeId / userId / credential は必須です")

    # チャレンジを取得して削除（リプレイ攻撃防止）
    challenge_item = consume_challenge(challenge_id)
    if not challenge_item:
        return error(400, "チャレンジが無効または期限切れです（再度ログインしてください）")

    if challenge_item["userId"] != user_id:
        return error(400, "ユーザー ID が一致しません")

    # クライアントから届く credential ID（base64url）
    raw_credential_id = credential_data.get("rawId") or credential_data.get("id", "")

    stored_credential = get_credential_by_id(raw_credential_id)
    if not stored_credential:
        return error(404, "認証情報が見つかりません。再登録が必要です。")

    expected_origin = get_expected_origin(event)

    # py_webauthn で署名を検証（生体データは受け取らない）
    # Lambda 処理時間を計測して PoC の1秒要件を検証する
    verify_start_ms = int(time.time() * 1000)
    try:
        verification = webauthn.verify_authentication_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_item["challenge"]),
            expected_rp_id=RP_ID,
            expected_origin=expected_origin,
            credential_public_key=as_bytes(stored_credential["publicKey"]),
            credential_current_sign_count=int(stored_credential["signCount"]),
            require_user_verification=True,
        )
    except Exception as exc:
        print(f"[ERROR] 署名検証失敗: userId={user_id}, error={exc}")
        # 失敗カウンターを加算（精度計測）
        increment_auth_stats(
            user_id=stored_credential["userId"],
            credential_id=raw_credential_id,
            success=False,
        )
        return error(401, f"認証失敗: {str(exc)}")

    lambda_time_ms = int(time.time() * 1000) - verify_start_ms

    # 署名カウンターを更新（リプレイ攻撃の検出に使用）
    # カウンターが前回値以下なら、デバイスのクローンの疑いあり
    new_sign_count = verification.new_sign_count
    stored_sign_count = int(stored_credential["signCount"])

    if new_sign_count > 0 and new_sign_count <= stored_sign_count:
        print(f"[WARN] 署名カウンター異常: userId={user_id}, "
              f"stored={stored_sign_count}, new={new_sign_count}")
        increment_auth_stats(
            user_id=stored_credential["userId"],
            credential_id=raw_credential_id,
            success=False,
        )
        return error(401, "デバイスの整合性エラーが検出されました（カウンター異常）")

    update_sign_count(
        user_id=stored_credential["userId"],
        credential_id=raw_credential_id,
        new_count=new_sign_count,
    )

    # 成功カウンターを加算（精度計測）
    increment_auth_stats(
        user_id=stored_credential["userId"],
        credential_id=raw_credential_id,
        success=True,
    )

    print(f"[INFO] 認証成功: userId={user_id}, signCount={new_sign_count}, "
          f"lambdaTimeMs={lambda_time_ms}")

    return ok({
        "ok": True,
        "userId": user_id,
        "displayName": stored_credential.get("displayName", user_id),
        "message": "指紋認証によるログインに成功しました",
        # Lambda 側の処理時間（ms）: ブラウザ側計測と合わせてレイテンシ内訳を確認できる
        "lambdaTimeMs": lambda_time_ms,
    })
