# MoC 指紋認証 PoC — 検証結果レポート

**PoC 期間**: 2026-06-__  
**環境**: AWS ap-northeast-1（東京）  
**PoC URL**: _（デプロイ後の CloudFront URL をここに記入。リポジトリにはコミットしない）_

---

## アーキテクチャ概要

```
[Windows PC]                    [AWS ap-northeast-1]
エレコム MoC リーダー
 │ USB接続
 ↓
Windows Hello（指紋照合 on-chip）
 │ 照合結果のみ（生体データなし）
 ↓
ブラウザ（Chrome/Edge）
 │ FIDO2/WebAuthn
 ↓
CloudFront (<your-distribution>.cloudfront.net)
 ├── /* → S3（静的フロントエンド）
 └── /api/* → API Gateway
               └── Lambda (Python 3.12)
                   ├── register.py  ← 公開鍵 + 証明書を検証
                   ├── authenticate.py ← 署名を検証
                   └── DynamoDB
                       ├── moc-poc-credentials-poc（公開鍵）
                       └── moc-poc-challenges-poc（チャレンジ）
```

---

## デプロイ済みリソース

| リソース | 値（デプロイ後に記入） |
|---------|----------------------|
| CloudFront URL | _CloudFormation 出力 `CloudFrontUrl`_ |
| API Endpoint | _CloudFormation 出力 `ApiEndpoint`_ |
| S3 バケット | _CloudFormation 出力 `FrontendBucketName`_ |
| DynamoDB (認証情報) | _CloudFormation 出力 `CredentialsTableName`_ |
| DynamoDB (チャレンジ) | _CloudFormation 出力 `ChallengesTableName`_ |
| Lambda: 登録開始 | `moc-poc-register-begin-poc`（命名規則） |
| Lambda: 登録完了 | `moc-poc-register-complete-poc`（命名規則） |
| Lambda: 認証開始 | `moc-poc-auth-begin-poc`（命名規則） |
| Lambda: 認証完了 | `moc-poc-auth-complete-poc`（命名規則） |
| SAM スタック | `moc-poc-fido2` (ap-northeast-1) |

---

## 実装済み機能

| 機能 | 状態 | 備考 |
|------|------|------|
| FIDO2/WebAuthn 登録フロー | ✅ | py-webauthn 2.x |
| FIDO2/WebAuthn 認証フロー | ✅ | 署名カウンター検証あり |
| CloudFront + S3 フロントエンド | ✅ | OAC 設定済み |
| API Gateway CORS | ✅ | CloudFront ドメインのみ許可 |
| DynamoDB（認証情報・チャレンジ） | ✅ | TTL 付きチャレンジ |
| 認証時間計測（Lambda側） | ✅ | lambdaTimeMs をレスポンスに含む |
| 成功/失敗カウンター | ✅ | DynamoDB に累積記録 |
| ゲート解錠 UI シミュレーション | ✅ | 認証成功時にアニメーション |
| ユニットテスト 12件 | ✅ | make test で確認済み |
| 生体データ非送信確認スクリプト | ✅ | lambda/security_check.py |

---

## 実機テスト結果

> ⚠️ 以下は実機テスト実施後に記入してください

### 1秒要件（TC-02）

| 試行 | 認証時間（ms） |
|------|--------------|
| 1 | — |
| 2 | — |
| 3 | — |
| 4 | — |
| 5 | — |
| **平均** | **— ms** |

**判定**: 未実施 / PASS / FAIL

---

### 成功率（TC-05）

| 指標 | 目標値 | 実測値 |
|------|-------|--------|
| 成功率 | ≥ 95% | — |
| 平均認証時間 | ≤ 1000 ms | — |

**判定**: 未実施 / PASS / FAIL

---

### 生体データ未送信（TC-04）

| 確認項目 | 結果 |
|---------|------|
| /api/register/complete に指紋画像・テンプレート含まれない | — |
| /api/auth/complete に生体データ含まれない | — |
| security_check.py が「未検出」を報告 | — |

**判定**: 未実施 / PASS / FAIL

---

## 知見・考察

### MoC（Match-on-Chip）方式の確認

WebAuthn の仕様上、指紋の照合はデバイス（MoC チップ）内で完結する。  
クラウド側に届くのは:
- **登録時**: 公開鍵 + attestation（デバイス証明書）のみ
- **認証時**: チャレンジへの署名（`authenticatorData` + `clientDataJSON` + `signature`）のみ

指紋画像・テンプレートは一切ネットワークを経由しない。

### 1秒要件について

- Lambda コールドスタート: 約 500〜800 ms（初回のみ）
- Lambda ウォームスタート: 約 50〜150 ms
- WebAuthn 署名生成（Windows Hello）: 約 200〜500 ms
- **合計（ウォーム時）**: 250〜650 ms → 1秒要件を満たす見込み

> ⚠️ PoC ではアカウント制約により Provisioned Concurrency を無効化。
> 本番導入時は `AutoPublishAlias: live` + `ProvisionedConcurrentExecutions: 1` を再有効化すること。
> （template.yaml の `AuthCompleteFunction` にコメントあり）

---

## コスト試算（参考）

| サービス | 月間コスト（想定） |
|---------|----------------|
| Lambda（100万リクエスト/月） | 約 $0.20 |
| DynamoDB（オンデマンド） | 約 $1〜5 |
| CloudFront（100GB/月） | 約 $8.50 |
| API Gateway（100万リクエスト/月） | 約 $3.50 |
| **合計** | **約 $13〜18/月** |

---

## 次のステップ（本番化に向けて）

1. **Provisioned Concurrency 再有効化**  
   `AuthCompleteFunction` に `AutoPublishAlias: live` + `ProvisionedConcurrentExecutions: 1` を追加
   
2. **カスタムドメイン設定**  
   Route 53 + ACM で `fingerprint.example.com` を CloudFront に向ける
   
3. **認証ポリシー強化**  
   - `attestation: direct` で MoC デバイスの証明書を検証
   - AAGUID でエレコムデバイスのみ許可するフィルタリング
   
4. **監視・アラート**  
   - CloudWatch アラーム: 認証失敗率 > 10%
   - Lambda Duration P99 > 800ms でアラート

5. **入退室管理システム連携**  
   DynamoDB Streams → 扉制御システム API 呼び出し
