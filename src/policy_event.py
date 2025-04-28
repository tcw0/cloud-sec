"""
Helper functions to pull common fields from the CloudTrail event that
EventBridge sends into the Lambda function.
"""
from typing import Any, Mapping


def extract_actor(detail: Mapping[str, Any]) -> str:
    """Return the user/role that performed the IAM action."""
    return detail["userIdentity"]["userName"]


def extract_policy_arn(detail: Mapping[str, Any]) -> str | None:
    """
    Return the policy ARN being created/attached/updated.

    Handles:
      • CreatePolicy  → responseElements.policy.arn
      • Attach*Policy → requestParameters.policyArn
      • Put*Policy    → constructs a pseudo-ARN for inline policies
    """
    # Attach* managed policies
    arn = detail.get("requestParameters", {}).get("policyArn")
    if arn:
        return arn

    # CreatePolicy
    resp = detail.get("responseElements") or {}
    arn = resp.get("policy", {}).get("arn")
    if arn:
        return arn

    # Inline PutUser/PutRole/PutGroupPolicy
    if detail["eventName"].startswith("Put"):
        principal_type = detail["eventName"][3:-6].lower()
        principal_name = detail["requestParameters"][f"{principal_type}Name"]
        policy_name    = detail["requestParameters"]["policyName"]
        account_id     = detail["recipientAccountId"]
        return (
            f"arn:aws:iam::{account_id}:{principal_type}/{principal_name}"
            f"/policy/{policy_name}"
        )

    return None
