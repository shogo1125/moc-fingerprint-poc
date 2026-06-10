# MoC 指紋認証 PoC

MoC（Match-on-Chip）USB リーダー ＋ FIDO2/WebAuthn による認証 PoC。  
**指紋データはチップ内で完結し、クラウドには署名と公開鍵のみ送る。**

```
指 → [MoCチップ: 照合] → 成功/失敗のみ → ブラウザ
                              ↓ 署名
                         Lambda（公開鍵で検証）→ DynamoDB
```

## デプロイ後の確認

デプロイ完了後、CloudFormation スタック出力から URL を取得してください（リポジトリには実環境の URL を含めません）。

```bash
aws cloudformation describe-stacks \
  --stack-name moc-poc-fido2 \
  --region ap-northeast-1 \
  --query "Stacks[0].Outputs"
```

| 出力キー | 用途 |
|----------|------|
| `CloudFrontUrl` | ブラウザで開く PoC URL |
| `ApiEndpoint` | API 直アクセス（デバッグ用） |

実機テスト手順 → [`docs/integration-test.md`](docs/integration-test.md)  
検証結果レポート → [`docs/poc-results.md`](docs/poc-results.md)

---

## クイックスタート

```bash
# テスト実行
make test

# ローカル開発（手順表示）
make local

# AWS デプロイ（要 aws configure / sam cli）
make deploy
```

## 対応ハードウェア

| 型番 | 種別 | 価格 |
|---|---|---|
| エレコム CR-FI01UBK | USB ドングル | ¥6,800 |
| エレコム CR-FI50UBK | USB ケーブル | ¥8,980 |

Windows 10/11 + Windows Hello + Chrome/Edge 必須。

---

## ファイル構成

```
poc-fido2/
├── frontend/index.html       # 登録・ログイン UI（WebAuthn API）
├── lambda/
│   ├── register.py           # /api/register/begin|complete
│   ├── authenticate.py       # /api/auth/begin|complete
│   ├── utils.py              # DynamoDB・CORS・オリジン検証
│   ├── security_check.py     # HAR 解析（生体データ未送信の確認）
│   └── test_local.py         # ユニットテスト
├── infra/
│   ├── template.yaml         # SAM（S3/CloudFront/API GW/Lambda/DynamoDB）
│   ├── samconfig.toml.example  # デプロイ設定テンプレート（要コピー）
│   └── env.local.json
├── scripts/
│   ├── deploy.sh             # ビルド→デプロイ→S3同期
│   └── local-dev.sh
└── Makefile
```

---

## ローカル動作確認

### 前提

- Python 3.12+、AWS SAM CLI、Docker（DynamoDB Local 任意）
- MoC リーダー接続済み

### 手順

```bash
# ターミナル1: API
sam build -t infra/template.yaml
sam local start-api --env-vars infra/env.local.json -p 3001

# ターミナル2: フロント
cd frontend && python3 -m http.server 8080
```

→ http://localhost:8080 を開く（WebAuthn は localhost で動作可）

---

## AWS デプロイ

```bash
# 初回のみ: デプロイ設定をローカルに作成（git 管理外）
cp infra/samconfig.toml.example infra/samconfig.toml

./scripts/deploy.sh
# または make deploy
```

デプロイ後:

1. 出力の `CloudFrontUrl` を確認
2. `infra/samconfig.toml`（ローカルのみ）を更新して再デプロイ

```toml
parameter_overrides = [
  "StageName=poc",
  "RPId=dxxxxxxxxxxxxxx.cloudfront.net",
  "AllowedOrigin=https://dxxxxxxxxxxxxxx.cloudfront.net",
]
```

| 項目 | 値 |
|---|---|
| RP ID | CloudFront ドメイン（`https://` なし） |
| API パス | `/api/register/*`, `/api/auth/*` |
| フロント | CloudFront → S3、`/api/*` → API Gateway |

---

## PoC 確認チェックリスト

- [ ] MoC リーダーで指紋登録が完了する
- [ ] 同じユーザーで指紋ログインが成功する
- [ ] DevTools Network で POST Body に指紋データが**ない**
- [ ] `make security-check` または HAR で検証
- [ ] チャレンジがリクエストごとに変わる
- [ ] DynamoDB の `signCount` が認証のたびに増える

### セキュリティ検証

```bash
# サンプルペイロードの自動チェック
make security-check

# 実際の通信（Chrome DevTools → Save as HAR）
cd lambda && .venv/bin/python security_check.py capture.har
```

送信されるのは `attestationObject` / `clientDataJSON` / `signature` のみ。  
指紋画像・特徴点は**一切含まれない**。

---

## コスト見積もり（東京リージョン）

### 無料枠内（アカウント開設後 12 ヶ月）

| サービス | PoC 規模（〜50ユーザー） | 月額 |
|---|---|---|
| S3 / CloudFront / API GW / Lambda / DynamoDB | 小規模利用 | 無料枠 |
| ACM | SSL | ¥0 |
| Route 53（任意） | ホストゾーン | 約 ¥75 |
| **合計** | | **¥0〜75** |

### 無料枠終了後（PoC 継続・50ユーザー・月1,000認証）

| サービス | 月額目安 |
|---|---|
| S3 + CloudFront + API GW + Lambda + DynamoDB | 約 ¥30 |
| Route 53（使う場合） | 約 ¥75 |
| **合計** | **¥30〜110/月** |

Route 53 を使わず CloudFront 標準ドメインのみなら **¥30〜50/月**。

| シナリオ | 月額目安 |
|---|---|
| PoC 継続（最小） | ¥30〜110 |
| 検証拡大（200ユーザー） | ¥300〜500 |
| 小規模本番（1,000ユーザー） | ¥1,000〜3,000 |

**ハードウェア初期費用:** リーダー 1 台 ¥6,800〜8,980

---

## 参考資料

- [WebAuthn (W3C)](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [py_webauthn](https://github.com/duo-labs/py_webauthn)
