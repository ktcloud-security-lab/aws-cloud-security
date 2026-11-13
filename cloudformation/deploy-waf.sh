#!/usr/bin/env bash
# KT Cloud Security Lab - deploy or update the WAF on the existing ALB
# Usage: bash cloudformation/deploy-waf.sh [Count|Block]
set -euo pipefail

REGION="ap-northeast-2"
EXPECTED_ACCOUNT="649852688812"
ALB_NAME="404-web-alb"
STACK_NAME="kt-waf-stack"
RULE_MODE="${1:-Count}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/waf.yaml"

if [[ "$RULE_MODE" != "Count" && "$RULE_MODE" != "Block" ]]; then
  echo "Usage: bash cloudformation/deploy-waf.sh [Count|Block]" >&2
  exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Template not found: $TEMPLATE" >&2
  exit 1
fi

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$ACCOUNT" != "$EXPECTED_ACCOUNT" ]]; then
  echo "Wrong AWS account: $ACCOUNT (expected $EXPECTED_ACCOUNT). Deployment cancelled." >&2
  exit 1
fi

ALB_ARN="$(aws elbv2 describe-load-balancers \
  --names "$ALB_NAME" \
  --region "$REGION" \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text)"

if [[ "$ALB_ARN" != arn:aws:elasticloadbalancing:*:loadbalancer/app/* ]]; then
  echo "ALB not found or returned an invalid ARN: $ALB_ARN" >&2
  exit 1
fi

printf 'AWS account: %s\nALB: %s\nStack: %s\nRule mode: %s\n' \
  "$ACCOUNT" "$ALB_NAME" "$STACK_NAME" "$RULE_MODE"

aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE" \
  --parameter-overrides \
    "ExistingAlbArn=$ALB_ARN" \
    "RuleMode=$RULE_MODE" \
  --region "$REGION" \
  --no-fail-on-empty-changeset

echo "WAF deployment finished. Verify CloudFormation stack and WAF association in the console."
