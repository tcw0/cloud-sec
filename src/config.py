"""Static configuration loaded from Lambda environment variables."""
import os

HISTORY_TABLE: str = "IamPolicyHistory"
SLACK_SECRET: str = "Slack/IAMNotifier"       # Secrets Manager name
HASH_ALGO: str = os.getenv("HASH_ALGO", "sha256")       # easy override later
TTL_DAYS: int = int(os.getenv("TTL_DAYS", "180"))       # DynamoDB row expiry
