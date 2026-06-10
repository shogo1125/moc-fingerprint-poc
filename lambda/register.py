"""
FIDO2/WebAuthn 登録ハンドラ
MoC指紋認証 PoC — Relying Party（登録フェーズ）

エンドポイント:
  POST /register/begin    → チャレンジ発行
  POST /register/complete → 公開鍵の検証・保存
"""

import json
import os

import webauthn
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from utils import (
    ok,
    error,
    options_response,
    save_challenge,
    consume_challenge,
    save_credential,
    get_credentials_for_user,
    get_expected_origin,
)

# Relying Party 設定（環境変数から取得）
RP_ID = os.environ["RP_ID"]
RP_NAME = os.environ["RP_NAME"]


# -------------------------------------------------------
# POST /register/begin
# -------------------------------------------------------
def begin_handler(event: dict, context) -> dict:
    """
    登録チャレンジを発行する。

    リクエスト Body:
        {
            "userId":      "user@example.com",  // ユーザーID（メール等）
            "displayName": "山田 太郎"           // 表示名
        }

    レスポンス:
        WebAuthn PublicKeyCredentialCreationOptions（JSON）
        + challengeId（チャレンジを後で消費するための ID）
    """
    # OPTIONS（CORS プリフライト）を処理
    if event.get("httpMethod") == "OPTIONS":
        return options_response()

    # リクエスト Body のパース
    try:
        body = json.loads(event.get("body") or "{}")
        user_id: str = body["userId"]
        display_name: str = body.get("displayName", user_id)
    except (KeyError, json.JSONDecodeError):
        return error(400, "userId は必須です")

    # 既に登録済みの credential を除外リストに追加
    # （同じデバイスを二重登録しないようにする）
    existing_credentials = get_credentials_for_user(user_id)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credentialId"]))
        for c in existing_credentials
    ]

    # py_webauthn でチャレンジと登録オプションを生成
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        # userId は bytes にする（FIDO2 仕様）
        user_id=user_id.encode("utf-8"),
        user_name=user_id,
        user_display_name=display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            # ユーザー検証を必須にする
            # → MoCリーダーが指紋照合成功時のみ署名を生成する
            user_verification=UserVerificationRequirement.REQUIRED,
            # resident_key: デバイスに credential を保存する（パスキー方式）
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        # 対応署名アルゴリズム（ES256: MoCリーダーが一般的に使用）
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,   # ES256 (P-256)
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # RS256
        ],
        exclude_credentials=exclude_credentials,
        timeout=60000,  # 60秒
    )

    # チャレンジを DynamoDB に保存（5分 TTL）
    challenge_id = save_challenge(
        challenge=bytes_to_base64url(options.challenge),
        user_id=user_id,
    )

    # クライアントに返すオプション（JSON シリアライズ）
    options_json = webauthn.options_to_json(options)
    options_dict = json.loads(options_json)

    # challengeId を追加（complete で使用）
    options_dict["challengeId"] = challenge_id
    options_dict["userId_str"] = user_id  # 画面表示用

    return ok(options_dict)


# -------------------------------------------------------
# POST /register/complete
# -------------------------------------------------------
def complete_handler(event: dict, context) -> dict:
    """
    MoCリーダーからの公開鍵と attestation を検証して保存する。

    リクエスト Body:
        {
            "challengeId": "...",      // begin で受け取った ID
            "userId":      "...",      // ユーザー ID
            "credential":  { ... }     // navigator.credentials.create() の結果
        }

    レスポンス:
        {"ok": true, "credentialId": "..."}
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

    # チャレンジを取得して削除（1回限り）
    challenge_item = consume_challenge(challenge_id)
    if not challenge_item:
        return error(400, "チャレンジが無効または期限切れです")

    # チャレンジが同じユーザーのものか確認
    if challenge_item["userId"] != user_id:
        return error(400, "ユーザー ID が一致しません")

    expected_origin = get_expected_origin(event)

    # py_webauthn で MoCリーダーからの attestation を検証
    try:
        verification = webauthn.verify_registration_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_item["challenge"]),
            expected_rp_id=RP_ID,
            expected_origin=expected_origin,
            # attestation 検証: PoC では "none" でも可
            # 本番では "direct" or "indirect" を推奨
            require_user_verification=True,
        )
    except Exception as exc:
        print(f"[ERROR] attestation 検証失敗: {exc}")
        return error(400, f"登録検証エラー: {str(exc)}")

    credential_id = bytes_to_base64url(verification.credential_id)

    # 公開鍵を DynamoDB に保存（credentialId は base64url で統一）
    save_credential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        display_name=body.get("displayName", user_id),
    )

    print(f"[INFO] 登録完了: userId={user_id}, credentialId={credential_id[:16]}...")

    return ok({
        "ok": True,
        "credentialId": credential_id,
        "message": "指紋認証デバイスの登録が完了しました",
    })
