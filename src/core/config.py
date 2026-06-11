"""
Lab 11 - Configuration & API Key Setup
"""
import os


def setup_api_key():
    """Load Google API key or continue in offline simulation mode.

    Offline mode is useful for local guardrail testing because most lab
    requirements are deterministic safety checks, not model-quality claims.
    """
    if "GOOGLE_API_KEY" not in os.environ:
        if os.environ.get("LAB11_REQUIRE_API_KEY") == "1":
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
        else:
            print("GOOGLE_API_KEY not set; using offline simulated agent where possible.")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    if "GOOGLE_API_KEY" in os.environ:
        print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
