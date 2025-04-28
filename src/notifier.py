"""
Main Lambda handler: detects IAM-policy changes, stores version hashes, and
sends a unified diff to Slack.
"""
from __future__ import annotations

import boto3
import hashlib
import json
import logging
import os
import datetime
import difflib
from typing import Any, Mapping

import requests
from botocore.exceptions import ClientError

from config import HISTORY_TABLE, SLACK_SECRET, TTL_DAYS
from policy_event import extract_actor, extract_policy_arn

# ────────────────────────── AWS clients ──────────────────────────
dynamodb = boto3.resource("dynamodb")
tbl      = dynamodb.Table(HISTORY_TABLE)
iam      = boto3.client("iam")
secrets  = boto3.client("secretsmanager")

# ────────────────────────── logging setup ─────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ───────────────────── helper: fetch Slack webhook ─────────────────
def _get_webhook_url() -> str:
    """Pull and cache the Slack Incoming-Webhook URL from Secrets Manager."""
    secret_val = secrets.get_secret_value(SecretId=SLACK_SECRET)
    secret_obj = json.loads(secret_val["SecretString"])
    return secret_obj["WebhookUrl"]


WEBHOOK_URL: str = _get_webhook_url()


# ───────────── helper: calc SHA-256 hash of the policy JSON ─────────
def _sha256(obj: Mapping[str, Any]) -> str:
    payload = json.dumps(obj, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


# ───────────── helper: store / compare hash in DynamoDB ────────────
def _record_and_diff(
    policy_arn: str,
    version_stamp: str,
    policy_json: Mapping[str, Any],
    actor: str,
    event_name: str,
    event_time: str,
) -> tuple[bool, Mapping[str, Any] | None]:
    """
    Put a new record if the hash is different.

    Returns (is_new_version, previous_item_or_None).
    """
    new_hash = _sha256(policy_json)

    # Lookup the latest version for this policy
    resp = tbl.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("PolicyArn").eq(policy_arn),
        Limit=1,
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    prev = items[0] if items else None
    if prev and prev["JsonHash"] == new_hash:
        return False, prev

    # Put the new record
    expire_at = int(
        (datetime.datetime.utcnow() + datetime.timedelta(days=TTL_DAYS)).timestamp()
    )
    tbl.put_item(
        Item={
            "PolicyArn": policy_arn,
            "VersionStamp": version_stamp,
            "JsonHash": new_hash,
            "CreatedBy": actor,
            "EventName": event_name,
            "EventTime": event_time,
            "ExpireAt": expire_at,
            "Json": policy_json,
        }
    )
    return True, prev


# ───────────── helper: unified diff between two dicts ──────────────
def _make_diff(old: Mapping[str, Any] | None, new: Mapping[str, Any]) -> str:
    old_lines = json.dumps(old or {}, indent=2, sort_keys=True).splitlines()
    new_lines = json.dumps(new,      indent=2, sort_keys=True).splitlines()
    return "\n".join(
        difflib.unified_diff(old_lines, new_lines, fromfile="prev", tofile="new", lineterm="")
    )[:3500]


# ────────────────────────── main handler ───────────────────────────
def lambda_handler(event, _context):
    logger.info("received event %s", json.dumps(event))

    detail = event["detail"]
    actor  = extract_actor(detail)
    ename  = detail["eventName"]
    etime  = detail["eventTime"]

    # Find the policy ARN & JSON
    policy_arn, policy_json = _resolve_policy(detail)
    if not policy_json:
        logger.warning("Policy JSON could not be resolved; skipping alert")
        return {"skip": True}

    # Store/compare hash
    is_new, prev_item = _record_and_diff(
        policy_arn,
        detail.get("requestID", datetime.datetime.utcnow().isoformat()),
        policy_json,
        actor,
        ename,
        etime,
    )
    if not is_new:
        logger.info("No change detected for %s", policy_arn)
        return {"changed": False}

    # Build and send Slack message
    diff_text = _make_diff(prev_item["Json"] if prev_item else None, policy_json)
    slack_msg = (
        f"*{ename}* by *{actor}* on `<https://console.aws.amazon.com/iam/home#/policies/{policy_arn}|{policy_arn}>`"
        f" at {etime}\n```{diff_text}```"
    )
    _post_to_slack(slack_msg)

    return {"changed": True}


# ───────────────── internal helpers ────────────────────────────────
def _post_to_slack(text: str):
    resp = requests.post(WEBHOOK_URL, json={"text": text})
    if resp.status_code >= 300:
        logger.error("Slack returned %s: %s", resp.status_code, resp.text)


def _resolve_policy(detail: Mapping[str, Any]) -> tuple[str | None, Mapping[str, Any] | None]:
    """
    Get (policy_arn, policy_json) for any IAM policy write event.
    Returns (None, None) if unable to resolve.
    """
    arn = extract_policy_arn(detail)
    if not arn:
        return None, None

    try:
        if detail["eventName"] == "CreatePolicy" or "Attach" in detail["eventName"]:
            version_id = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            pol_doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]
            return arn, pol_doc

        # Inline Put*Policy: JSON is already in requestParameters
        pol_doc = json.loads(detail["requestParameters"]["policyDocument"])
        return arn, pol_doc

    except ClientError as exc:
        logger.error("IAM/API error resolving %s: %s", arn, exc)
        return arn, None


