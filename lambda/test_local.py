"""
ローカル結合テスト用スクリプト
MoC指紋認証 PoC — Lambda 関数の単体テスト

実行方法:
  cd poc-fido2/lambda
  pip install -r requirements.txt pytest
  pytest test_local.py -v

注意:
  このテストはモックを使用します。
  実際のMoCリーダーとの結合テストは、
  SAM Local + フロントエンドで行います（README 参照）。
"""

import json
import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

# 環境変数をテスト用に設定
os.environ["CREDENTIALS_TABLE"] = "moc-poc-credentials-test"
os.environ["CHALLENGES_TABLE"]  = "moc-poc-challenges-test"
os.environ["RP_ID"]             = "localhost"
os.environ["RP_NAME"]           = "MoC PoC Test"
os.environ["ALLOWED_ORIGIN"]    = "http://localhost:8080"


class TestUtils(unittest.TestCase):
    """utils.py のユニットテスト"""

    def test_ok_response_has_cors_headers(self):
        """OKレスポンスに CORS ヘッダーが含まれること"""
        from utils import ok
        response = ok({"result": "success"})
        self.assertEqual(response["statusCode"], 200)
        self.assertIn("Access-Control-Allow-Origin", response["headers"])
        body = json.loads(response["body"])
        self.assertEqual(body["result"], "success")

    def test_error_response_structure(self):
        """エラーレスポンスの構造が正しいこと"""
        from utils import error
        response = error(400, "テストエラー")
        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error"], "テストエラー")

    def test_options_response_for_cors_preflight(self):
        """CORS プリフライトに 200 を返すこと"""
        from utils import options_response
        response = options_response()
        self.assertEqual(response["statusCode"], 200)

    def test_save_and_consume_challenge(self):
        """チャレンジを保存→取得→削除できること"""
        # _dynamodb はモジュールロード時に初期化されるため、
        # get_challenges_table() 経由でテーブルオブジェクトをモックする
        mock_table = MagicMock()

        # delete_item が保存した値を返すようにモック
        saved_item = {
            "challengeId": "test-uuid",
            "challenge": "aabbccdd",
            "userId": "user@example.com",
            "expiresAt": int(time.time()) + 300,
        }
        mock_table.delete_item.return_value = {"Attributes": saved_item}

        with patch("utils.get_challenges_table", return_value=mock_table):
            from utils import consume_challenge
            result = consume_challenge("test-uuid")

        self.assertIsNotNone(result)
        self.assertEqual(result["userId"], "user@example.com")


class TestRegisterBeginHandler(unittest.TestCase):
    """register.begin_handler のテスト"""

    def _make_event(self, body: dict, method: str = "POST") -> dict:
        """Lambda イベントを生成するヘルパー"""
        return {
            "httpMethod": method,
            "headers": {"origin": "http://localhost:8080"},
            "body": json.dumps(body),
        }

    def test_options_preflight_returns_200(self):
        """OPTIONS リクエストが 200 を返すこと"""
        from register import begin_handler
        event = self._make_event({}, method="OPTIONS")
        response = begin_handler(event, None)
        self.assertEqual(response["statusCode"], 200)

    def test_missing_user_id_returns_400(self):
        """userId が無いと 400 を返すこと"""
        from register import begin_handler
        event = self._make_event({"displayName": "テスト"})
        response = begin_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    def test_invalid_json_returns_400(self):
        """不正な JSON が 400 を返すこと"""
        from register import begin_handler
        event = {
            "httpMethod": "POST",
            "headers": {},
            "body": "not-json",
        }
        response = begin_handler(event, None)
        self.assertEqual(response["statusCode"], 400)


class TestAuthBeginHandler(unittest.TestCase):
    """authenticate.begin_handler のテスト"""

    def _make_event(self, body: dict) -> dict:
        return {
            "httpMethod": "POST",
            "headers": {"origin": "http://localhost:8080"},
            "body": json.dumps(body),
        }

    def test_missing_user_id_returns_400(self):
        """userId が無いと 400 を返すこと"""
        from authenticate import begin_handler
        event = self._make_event({})
        response = begin_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    @patch("authenticate.get_credentials_for_user", return_value=[])
    def test_unregistered_user_returns_404(self, _mock):
        """未登録ユーザーは 404 を返すこと"""
        from authenticate import begin_handler
        event = self._make_event({"userId": "unknown@example.com"})
        response = begin_handler(event, None)
        self.assertEqual(response["statusCode"], 404)


class TestSecurityChecks(unittest.TestCase):
    """セキュリティ要件のテスト"""

    def test_challenge_ttl_is_reasonable(self):
        """チャレンジの有効期限が適切な範囲に設定されていること（1分〜10分）"""
        from utils import CHALLENGE_TTL_SECONDS
        self.assertGreaterEqual(CHALLENGE_TTL_SECONDS, 60,   "有効期限が短すぎます")
        self.assertLessEqual(CHALLENGE_TTL_SECONDS,   600,  "有効期限が長すぎます（10分以内）")

    @patch("authenticate.consume_challenge", return_value=None)
    def test_expired_challenge_returns_400(self, _mock):
        """期限切れチャレンジは 400 を返すこと（リプレイ攻撃防止）"""
        from authenticate import complete_handler
        event = {
            "httpMethod": "POST",
            "headers": {},
            "body": json.dumps({
                "challengeId": "expired-id",
                "userId": "user@example.com",
                "credential": {},
            }),
        }
        response = complete_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    def test_rp_id_configured(self):
        """RP_ID が環境変数で設定されていること"""
        from register import RP_ID
        self.assertIsNotNone(RP_ID)
        self.assertNotEqual(RP_ID, "")


if __name__ == "__main__":
    # テストの実行
    print("=" * 60)
    print("MoC指紋認証 PoC — ローカルユニットテスト")
    print("=" * 60)
    unittest.main(verbosity=2)
