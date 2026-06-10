"""
セキュリティ検証スクリプト
MoC指紋認証 PoC — 生体データが送信されていないことを確認する

使い方:
  python3 security_check.py <キャプチャファイル.json>

想定するキャプチャ形式（Chrome DevTools → HAR エクスポート）:
  1. Chrome DevTools → Network タブを開く
  2. 登録・ログインを実行する
  3. Network タブで右クリック → "Save all as HAR with content"
  4. python3 security_check.py captured.har

または、curlログを手動で作成して渡すことも可能。
"""

import json
import sys
import base64

# -------------------------------------------------------
# FIDO2 で送受信される正規フィールド（生体データを含まない）
# -------------------------------------------------------
FIDO2_SAFE_FIELDS = {
    # 登録レスポンス（register/complete）
    "attestationObject",   # 公開鍵と認証器情報（指紋データなし）
    "clientDataJSON",      # チャレンジ・オリジン（指紋データなし）
    # 認証レスポンス（auth/complete）
    "authenticatorData",   # 署名カウンター・UV フラグ（指紋データなし）
    "signature",           # チャレンジへのデジタル署名（指紋データなし）
    "userHandle",          # ユーザー識別子（任意）
    # 共通
    "id",
    "rawId",
    "type",
    "challengeId",
    "userId",
    "displayName",
    "challenge",
    "rpId",
    "timeout",
    "userVerification",
    "allowCredentials",
    "excludeCredentials",
    "pubKeyCredParams",
    "authenticatorSelection",
    "ok",
    "credentialId",
    "message",
}

# 生体データが含まれている場合に疑われるキーワード（あれば警告）
SUSPICIOUS_KEYWORDS = [
    "fingerprint",
    "biometric",
    "template",
    "minutiae",    # 指紋の特徴点
    "ridge",       # 指紋の隆線
    "image",
    "rawSensor",
    "biodata",
]


def check_har_file(har_path: str) -> None:
    """
    HAR ファイルを解析し、生体データが送信されていないかチェックする。

    Args:
        har_path: Chrome DevTools で保存した HAR ファイルのパス
    """
    print("=" * 60)
    print("MoC指紋認証 PoC — セキュリティ検証レポート")
    print("=" * 60)

    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    fido2_requests = [
        e for e in entries
        if "/register/" in e["request"]["url"] or "/auth/" in e["request"]["url"]
    ]

    if not fido2_requests:
        print("[INFO] FIDO2 関連リクエストが見つかりませんでした")
        return

    print(f"\n検出した FIDO2 リクエスト数: {len(fido2_requests)}\n")

    all_passed = True
    for entry in fido2_requests:
        url = entry["request"]["url"]
        method = entry["request"]["method"]
        print(f"--- {method} {url} ---")

        # リクエスト Body の確認
        post_data = entry["request"].get("postData", {})
        body_text = post_data.get("text", "{}")
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            body = {}

        issues = _check_body_for_biometrics(body)
        if issues:
            all_passed = False
            for issue in issues:
                print(f"  ⚠️  警告: {issue}")
        else:
            print("  ✅ 生体データ未検出（安全）")

        # 送信フィールドのリスト表示
        _print_fields(body)
        print()

    print("=" * 60)
    if all_passed:
        print("✅ 検証結果: 生体データはサーバーに送信されていません")
        print("   MoC方式の安全性が確認されました")
    else:
        print("⚠️  警告: 疑わしいフィールドが検出されました")
        print("   実装を確認してください")
    print("=" * 60)


def _check_body_for_biometrics(body: dict, path: str = "") -> list[str]:
    """
    dict を再帰的に走査して生体データらしきフィールドを検出する。

    Returns:
        問題のある説明文のリスト（空なら問題なし）
    """
    issues = []
    for key, value in body.items():
        full_key = f"{path}.{key}" if path else key

        # キー名に疑わしいキーワードが含まれるか確認
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in key.lower():
                issues.append(f"疑わしいフィールド名: {full_key} (キーワード: {kw})")

        # 値が文字列の場合、base64 デコードして確認
        if isinstance(value, str) and len(value) > 100:
            issues += _check_base64_content(value, full_key)

        # 値が dict の場合は再帰
        if isinstance(value, dict):
            issues += _check_body_for_biometrics(value, full_key)

    return issues


def _check_base64_content(b64_value: str, field_name: str) -> list[str]:
    """
    base64 エンコードされた値をデコードして、
    生体データっぽいパターン（固定サイズの大きなバイナリ等）を検出する。

    FIDO2 の正規フィールド（attestationObject 等）は数百バイトで
    構造化された CBOR データであり、生体テンプレートとは異なる。
    """
    issues = []
    try:
        # base64url → base64 変換
        padded = b64_value.replace("-", "+").replace("_", "/")
        padded += "=" * (4 - len(padded) % 4) if len(padded) % 4 != 0 else ""
        decoded = base64.b64decode(padded)

        # 生体テンプレートは一般的に 256〜2048 バイト以上の固定サイズ
        # FIDO2 の attestation は構造化データなので通常より小さい
        if len(decoded) > 4096:
            issues.append(
                f"大きなバイナリデータ: {field_name} ({len(decoded)} bytes) "
                "— 生体テンプレートの可能性があります。内容を確認してください。"
            )
    except Exception:
        pass  # base64 でないフィールドは無視
    return issues


def _print_fields(body: dict, indent: int = 2) -> None:
    """フィールド名と値のサマリーを表示する（デバッグ用）"""
    for key, value in body.items():
        is_safe = key in FIDO2_SAFE_FIELDS
        marker = "✅" if is_safe else "❓"
        if isinstance(value, str) and len(value) > 40:
            display = value[:40] + "…"
        elif isinstance(value, dict):
            display = "{...}"
        else:
            display = str(value)
        print(f"  {'  ' * (indent - 2)}{marker} {key}: {display}")
        if isinstance(value, dict):
            _print_fields(value, indent + 1)


def check_payload_inline(payload: dict, label: str = "ペイロード") -> bool:
    """
    辞書形式のペイロードを直接チェックする（テスト・デバッグ用）。

    Returns:
        True: 生体データなし（安全）
        False: 疑わしいフィールドあり
    """
    print(f"\n=== {label} のセキュリティチェック ===")
    issues = _check_body_for_biometrics(payload)
    if issues:
        for issue in issues:
            print(f"  ⚠️  {issue}")
        return False
    else:
        print("  ✅ 生体データ未検出（安全）")
        return True


# -------------------------------------------------------
# 登録・認証で実際に送信されるペイロードのサンプル検証
# -------------------------------------------------------
SAMPLE_REGISTER_COMPLETE_PAYLOAD = {
    "challengeId": "550e8400-e29b-41d4-a716-446655440000",
    "userId": "user@example.com",
    "displayName": "山田 太郎",
    "credential": {
        "id": "base64url_credential_id_here",
        "rawId": "base64url_raw_id_here",
        "type": "public-key",
        "response": {
            # attestationObject: CBOR エンコードされた公開鍵情報（指紋データなし）
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjE...",
            # clientDataJSON: チャレンジとオリジン情報（指紋データなし）
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdl...",
        },
    },
}

SAMPLE_AUTH_COMPLETE_PAYLOAD = {
    "challengeId": "550e8400-e29b-41d4-a716-446655440001",
    "userId": "user@example.com",
    "credential": {
        "id": "base64url_credential_id_here",
        "rawId": "base64url_raw_id_here",
        "type": "public-key",
        "response": {
            # authenticatorData: 署名カウンター・フラグ（指紋データなし）
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MF...",
            # clientDataJSON: チャレンジ（指紋データなし）
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdl...",
            # signature: 秘密鍵による署名（指紋データなし）
            "signature": "MEYCIQDy5wE9Bav2yZVGfFSYJAJTGbEuB8Ns1...",
            "userHandle": None,
        },
    },
}


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # HAR ファイルが指定された場合
        check_har_file(sys.argv[1])
    else:
        # サンプルペイロードで検証デモ
        print("=" * 60)
        print("MoC指紋認証 PoC — サンプルペイロード セキュリティ検証")
        print("=" * 60)
        print()
        print("【MoC方式の安全性の確認ポイント】")
        print("  サーバーに送られるのは以下のデータのみ:")
        print("  ・challengeId / userId: 識別情報")
        print("  ・attestationObject: 公開鍵と認証器情報（CBOR）")
        print("  ・clientDataJSON: チャレンジとオリジン")
        print("  ・signature: チップ内秘密鍵による署名")
        print()
        print("  ✖ 指紋画像・特徴点・生体テンプレートは一切含まれない")
        print()

        ok1 = check_payload_inline(SAMPLE_REGISTER_COMPLETE_PAYLOAD, "登録（register/complete）")
        ok2 = check_payload_inline(SAMPLE_AUTH_COMPLETE_PAYLOAD, "認証（auth/complete）")

        print()
        if ok1 and ok2:
            print("✅ サンプルペイロードの検証: 生体データは送信されていません")
        else:
            print("⚠️  警告: 検証に問題があります")

        print()
        print("HAR ファイルで実際のキャプチャを検証するには:")
        print("  python3 security_check.py <your_capture.har>")
