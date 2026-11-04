"""Uncalibrated score policy shared by web and validation audit."""

RISK_THRESHOLD = 0.50
DANGER_THRESHOLD = 0.65


def risk_decision(benign_score: float) -> tuple[float, bool, str]:
    risk_score = max(0.0, min(1.0, 1.0 - float(benign_score)))
    flag = risk_score >= RISK_THRESHOLD
    level = "safe" if not flag else ("suspicious" if risk_score < DANGER_THRESHOLD else "dangerous")
    return risk_score, flag, level
