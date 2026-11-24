from typing import Any, Dict, List, Tuple


REQUIRED_S3_ACTIONS = {
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket",
}

FORBIDDEN_ACTION_PATTERNS = {
    "*",
    "s3:*",
    "iam:*",
    "*:*",
}


def _normalize_list(val: Any) -> List[str]:
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(x) for x in val]
    return []


def verify_policy(
    statements: List[Dict[str, Any]],
    target_bucket: str,
) -> Tuple[bool, float, List[str], str]:
    violations: List[str] = []
    allowed_bucket_actions: set[str] = set()
    allowed_object_actions: set[str] = set()

    if not statements:
        return False, 0.0, ["Empty policy: no statements provided."], "FAILED (empty policy)"

    for idx, stmt in enumerate(statements):
        effect = stmt.get("Effect")
        actions = _normalize_list(stmt.get("Action"))
        resources = _normalize_list(stmt.get("Resource"))

        if effect != "Allow":
            continue

        for act in actions:
            if act in FORBIDDEN_ACTION_PATTERNS or act.endswith(":*"):
                violations.append(f"Statement {idx}: overly broad action {act} is forbidden.")
            for res in resources:
                if res == "*":
                    violations.append(
                        f"Statement {idx}: wildcard resource * with action {act} is forbidden."
                    )
                elif res == target_bucket:
                    allowed_bucket_actions.add(act)
                elif res == f"{target_bucket}/*" or res.startswith(f"{target_bucket}/"):
                    allowed_object_actions.add(act)
                else:
                    violations.append(
                        f"Statement {idx}: out-of-scope resource {res} granted for {act}."
                    )

    missing_bucket = [a for a in ("s3:ListBucket",) if a not in allowed_bucket_actions]
    missing_obj = [a for a in ("s3:GetObject", "s3:PutObject") if a not in allowed_object_actions]

    if missing_bucket:
        violations.append(f"Missing required bucket-level actions on {target_bucket}: {missing_bucket}")
    if missing_obj:
        violations.append(
            f"Missing required object-level actions on {target_bucket}/*: {missing_obj}"
        )

    passed = len(violations) == 0
    reward = 1.0 if passed else 0.0
    summary = "PASSED: least privilege verified." if passed else f"FAILED ({len(violations)} issues)."
    return passed, reward, violations, summary
