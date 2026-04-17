from __future__ import annotations

import re
from itertools import zip_longest


def version_satisfies_all(version: str, constraints: list[str]) -> bool:
    return all(version_satisfies(version, constraint) for constraint in constraints)


def version_satisfies(version: str, constraint: str) -> bool:
    constraint = constraint.strip()
    operators = ["<=", ">=", "==", "!=", "<", ">"]
    operator = next((item for item in operators if constraint.startswith(item)), None)
    if operator is None:
        raise ValueError(f"Unsupported constraint: {constraint}")

    target = constraint[len(operator) :].strip()
    comparison = compare_versions(version, target)

    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    if operator == "==":
        return comparison == 0
    if operator == "!=":
        return comparison != 0

    raise ValueError(f"Unsupported operator: {operator}")


def compare_versions(left: str, right: str) -> int:
    left_parts = tokenize_version(left)
    right_parts = tokenize_version(right)

    for left_part, right_part in zip_longest(left_parts, right_parts, fillvalue=0):
        if left_part == right_part:
            continue

        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1

        left_text = str(left_part)
        right_text = str(right_part)
        return -1 if left_text < right_text else 1

    return 0


def tokenize_version(version: str) -> list[int | str]:
    tokens = re.split(r"[.\-+_]", version)
    normalized: list[int | str] = []
    for token in tokens:
        if token == "":
            continue
        if token.isdigit():
            normalized.append(int(token))
        else:
            normalized.append(token.lower())
    return normalized

