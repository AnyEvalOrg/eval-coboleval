"""Standard-library receipt authentication and the scorer's failure gate."""
import base64
import hashlib
import hmac
import json
import re


def verify_receipt(stdout: str, key: bytes) -> dict | None:
    """None means no authentic, well-formed supervisor envelope, not bad output."""
    try:
        envelope = json.loads(stdout)
        body, tag = envelope["body"], envelope["tag"]
        if not hmac.compare_digest(hmac.new(key, body.encode(), hashlib.sha256).hexdigest(), tag):
            return None
        receipt = json.loads(body)
        if (type(receipt["returncode"]) is not int
                or type(receipt["timeout"]) is not bool
                or type(receipt["overflow"]) is not bool
                or receipt.get("stage") not in {"compile", "run"}
                or not re.fullmatch(r"/tmp/cjt-[a-zA-Z0-9_-]+", receipt["cwd"])
                or type(receipt.get("cleanup_failed", False)) is not bool
                or type(receipt.get("supervisor_error", False)) is not bool):
            return None
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None

    # Authentication and supervisor-field validation have completed. Output is
    # candidate-controlled; malformed base64, field shape, or UTF-8 is a verdict.
    receipt["output_error"] = False
    try:
        if not isinstance(receipt["output"], str):
            raise ValueError("invalid output shape")
        receipt["output"] = base64.b64decode(receipt["output"], validate=True).decode("utf-8")
    except (ValueError, TypeError, KeyError, UnicodeError):
        receipt["output"] = ""
        receipt["output_error"] = True
    return receipt


def receipt_failure(receipt: dict) -> str | None:
    """Shared by the scorer and real Linux regressions; a reason means INCORRECT."""
    if receipt.get("output_error"):
        return "output not decodable"
    if receipt.get("cleanup_failed"):
        return "candidate cleanup failed"
    if receipt.get("supervisor_error"):
        return "candidate execution failed"
    if receipt["timeout"]:
        return f"{receipt['stage']} timeout"
    if receipt["overflow"]:
        return "output limit exceeded"
    if receipt["returncode"] != 0:
        return f"{receipt['stage']} error (exit {receipt['returncode']})"
    if receipt["stage"] != "run":
        return "run did not complete"
    return None
