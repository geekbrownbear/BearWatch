"""Curated software-to-CPE rules (intel/cpe_overrides.json)."""

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..config import get_settings


@dataclass(frozen=True)
class Rule:
    name: re.Pattern
    publisher: re.Pattern | None
    cpe: tuple[tuple[str, str], ...]
    winget: str | None

    def matches(self, display_name: str, publisher: str | None) -> bool:
        if not self.name.search(display_name):
            return False
        if self.publisher is not None and not self.publisher.search(publisher or ""):
            return False
        return True


def load_rules(path: Path) -> list[Rule]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = []
    for r in data["rules"]:
        rules.append(
            Rule(
                name=re.compile(r["name"], re.I),
                publisher=re.compile(r["publisher"], re.I) if r.get("publisher") else None,
                cpe=tuple((v, p) for v, p in r["cpe"]),
                winget=r.get("winget"),
            )
        )
    return rules


@lru_cache
def rules() -> list[Rule]:
    return load_rules(get_settings().overrides_path)


def resolve(display_name: str, publisher: str | None = None, rule_set: list[Rule] | None = None) -> Rule | None:
    for rule in rule_set if rule_set is not None else rules():
        if rule.matches(display_name.strip(), publisher):
            return rule
    return None
