#!/usr/bin/env bash
# MoC指紋認証 PoC — AWS デプロイ＋フロントエンド同期
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STACK_NAME="${STACK_NAME:-moc-poc-fido2}"
REGION="${AWS_REGION:-ap-northeast-1}"

cd "$ROOT"

# デプロイ設定がなければテンプレートから作成（samconfig.toml は git 管理外）
if [[ ! -f infra/samconfig.toml ]]; then
  cp infra/samconfig.toml.example infra/samconfig.toml
  echo "infra/samconfig.toml を example から作成しました"
fi

echo "==> SAM ビルド"
sam build -t infra/template.yaml

echo "==> SAM デプロイ"
sam deploy --config-file infra/samconfig.toml

echo "==> スタック出力を取得"
CF_URL=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontUrl'].OutputValue" \
  --output text)

BUCKET=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" \
  --output text)

echo "==> フロントエンドを S3 にアップロード"
aws s3 sync frontend/ "s3://${BUCKET}/" \
  --delete \
  --cache-control "max-age=3600"

echo ""
echo "デプロイ完了"
echo "  CloudFront URL : ${CF_URL}"
echo "  S3 バケット    : ${BUCKET}"
echo ""
echo "次の作業:"
echo "  1. infra/samconfig.toml（ローカル）の RPId を CloudFront ドメインに更新"
echo "     例: RPId=dxxxxxxxxxxxxxx.cloudfront.net"
echo "  2. AllowedOrigin を ${CF_URL} に設定して再デプロイ"
echo "  3. ${CF_URL} をブラウザで開いて MoC リーダーで検証"
