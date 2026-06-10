# MoC 指紋認証 PoC — 実機結合テスト手順書

**対象 URL**: _（デプロイ後の CloudFront URL を記入）_  
**日付**: 2026-06-__  
**テスター**: _______________

> URL の取得: `aws cloudformation describe-stacks --stack-name moc-poc-fido2 --region ap-northeast-1 --query "Stacks[0].Outputs[?OutputKey=='CloudFrontUrl'].OutputValue" --output text`

---

## 前提条件

| 項目 | 要件 |
|------|------|
| OS | Windows 10 / 11 |
| ブラウザ | Chrome 最新版 / Edge 最新版 |
| デバイス | エレコム CR-FI01UBK または CR-FI50UBK |
| 接続 | USB 接続、Windows Hello に登録済み |

> **注意**: macOS の Touch ID でも WebAuthn 自体は動作するが、  
> MoC（Match-on-Chip）の検証は Windows Hello + エレコムリーダーで行うこと。

---

## テスト環境セットアップ

```
Windows PC
  └─ USB ポート ──── エレコム MoC リーダー（CR-FI01UBK）
  └─ Chrome / Edge
       └─ https://<your-distribution>.cloudfront.net
                └─ /api/* → API Gateway → Lambda → DynamoDB
```

### 1. MoC リーダーの接続確認

1. デバイスマネージャーで `HID 準拠デバイス` として認識されているか確認
2. 設定 → アカウント → サインイン オプション → 指紋認識 に「Windows Hello 指紋」が表示されているか確認

---

## テストケース一覧

### TC-01: 指紋登録（正常系）

**目的**: MoC リーダーで指紋を登録し、公開鍵が DynamoDB に保存されることを確認する

**手順**:
1. Chrome で PoC URL（CloudFront）を開く
2. 「ユーザーID」に `test-user-01` を入力
3. 「登録」ボタンをクリック
4. ブラウザが Windows Hello の認証ダイアログを表示することを確認
5. MoC リーダーに指を置く
6. 「登録完了」のメッセージを確認

**期待結果**:
- [ ] Windows Hello ダイアログが表示される
- [ ] MoC リーダーの LED が点灯/点滅する（機種による）
- [ ] 「登録完了」または類似のメッセージが UI に表示される
- [ ] エラーなし

**実際の結果**: _______________  
**判定**: PASS / FAIL  

---

### TC-02: 指紋認証（正常系・1秒要件）

**目的**: 登録済み指紋で認証し、1秒以内に完了することを確認する

**手順**:
1. TC-01 完了後、「認証」ボタンをクリック
2. Windows Hello ダイアログが表示されたら MoC リーダーに指を置く
3. 認証時間（ms）を UI で確認する
4. ゲート解錠シミュレーションが表示されることを確認

**期待結果**:
- [ ] 認証時間 **≦ 1000 ms**（UI の計測値）
- [ ] 「認証成功」メッセージ表示
- [ ] ゲート解錠アニメーション表示
- [ ] `lambdaTimeMs` が応答 JSON に含まれる

**計測値記録**:

| 試行 | 認証時間（ms） | 判定 |
|------|--------------|------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 平均 | | |

**判定**: PASS / FAIL  

---

### TC-03: 異なる指での認証（異常系）

**目的**: 登録していない指では認証が失敗することを確認する

**手順**:
1. 「認証」ボタンをクリック
2. 登録していない指（例: 薬指）を MoC リーダーに置く
3. 結果を確認

**期待結果**:
- [ ] Windows Hello が認証を拒否する（「認識できません」等）
- [ ] または Lambda がエラー応答を返す
- [ ] UI にエラーメッセージが表示される

**実際の結果**: _______________  
**判定**: PASS / FAIL  

---

### TC-04: HAR 解析（生体データ未送信の確認）

**目的**: 指紋の生体データがネットワーク上を流れないことを確認する  
（MoC = Match-on-Chip の核心検証）

**手順**:
1. Chrome DevTools を開く（F12）
2. Network タブを選択、「Preserve log」にチェック
3. 「登録」→「認証」を一通り実行
4. HAR ファイルをエクスポート（右クリック → Save all as HAR with content）
5. HAR ファイルを `docs/har/poc-test-YYYYMMDD.har` に保存
6. 以下のコマンドで生体データの有無を確認:

```bash
cd poc-fido2
.venv/bin/python lambda/security_check.py docs/har/poc-test-YYYYMMDD.har
```

**期待結果**:
- [ ] `/api/register/complete` のリクエストボディに `publicKey`, `attestationObject` は含まれるが指紋画像・テンプレートは含まれない
- [ ] `/api/auth/complete` のリクエストボディに `signature`, `authenticatorData` は含まれるが生体データは含まれない
- [ ] security_check.py が「生体データ: 未検出」を報告する

**実際の結果**: _______________  
**判定**: PASS / FAIL  

---

### TC-05: 成功率の確認

**目的**: 10 回認証を試行し、成功率 ≥ 95% を確認する

**手順**:
1. 「認証」を 10 回繰り返す
2. 各結果を記録する

| 試行 | 結果（○/×） | 認証時間（ms） |
|------|-----------|--------------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |
| **合計** | **成功: ___ 回** | **平均: ___ ms** |

**成功率**: ___ % (目標: ≥ 95%)  
**判定**: PASS / FAIL  

---

### TC-06: DynamoDB カウンター確認

**目的**: 成功/失敗カウンターが DynamoDB に正しく記録されていることを確認する

**手順**:
```bash
aws dynamodb scan \
  --table-name moc-poc-credentials-poc \
  --region ap-northeast-1 \
  --query "Items[*].{userId:userId.S,successCount:authSuccessCount.N,failCount:authFailCount.N}"
```

**期待結果**:
- [ ] `authSuccessCount` が TC-05 の成功回数と一致
- [ ] `authFailCount` が TC-03 の失敗回数と一致

**実際の結果**: _______________  
**判定**: PASS / FAIL  

---

## テスト結果サマリー

| TC | テスト名 | 判定 | 備考 |
|----|---------|------|------|
| TC-01 | 指紋登録（正常系） | | |
| TC-02 | 認証 1秒要件 | | |
| TC-03 | 異常系（異指） | | |
| TC-04 | 生体データ未送信 | | |
| TC-05 | 成功率 95% | | |
| TC-06 | DynamoDB カウンター | | |

**総合判定**: PASS / FAIL  
**テスト日時**: _______________  
**テスター署名**: _______________  

---

## トラブルシューティング

### エラー: "このデバイスでは指紋認証がサポートされていません"
→ Windows Hello の指紋設定が完了しているか確認  
→ Chrome/Edge を最新版に更新する

### エラー: "認証情報が見つかりません。再登録が必要です。"
→ 先に「登録」を実行してから「認証」を行う

### エラー: "チャレンジが無効または期限切れです"
→ 60秒以内に認証操作を完了させる

### エラー: CORS エラー（DevTools コンソール）
→ `infra/samconfig.toml`（ローカル）の `AllowedOrigin` が PoC URL と一致しているか確認  
→ 再デプロイ: `make deploy`
