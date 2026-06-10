#!/usr/bin/env bash
# MoC指紋認証 PoC — ローカル開発環境の起動手順
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/lambda"

# 仮想環境がなければ作成
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt pytest
fi

echo "==> ユニットテスト"
.venv/bin/pytest test_local.py -q

echo ""
echo "ローカル起動手順（ターミナルを2つ使う）:"
echo ""
echo "  [ターミナル1] SAM Local API"
echo "    cd $ROOT"
echo "    sam build -t infra/template.yaml"
echo "    sam local start-api --env-vars infra/env.local.json -p 3001"
echo ""
echo "  [ターミナル2] フロントエンド"
echo "    cd $ROOT/frontend"
echo "    python3 -m http.server 8080"
echo ""
echo "  ブラウザ: http://localhost:8080"
echo "  MoC リーダーを USB 接続して登録・ログインを試す"
