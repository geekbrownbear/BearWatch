"""Posture rules: Windows settings that make a device easier to attack (see docs/posture.md).

The rules live in intel/posture_rules.toml. The server turns them into a list of reads, agents
read those values from the registry (only inside ALLOWED_KEYS, the same list the agent enforces)
and send them back with their inventory, and `evaluate` judges them here. A failed rule becomes
a finding with source "posture", so it gets a fix row, a risk score, a deadline and exceptions
like any CVE.

Values from the agent:
  int      a DWORD or QWORD, or a text value that is a plain number
  True     the key exists (a read with no ":value" part)
  False    the key does not exist
  "set"    the value exists but is text, binary, or has a name that could hold a secret
  None     the value does not exist
"""

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

from sqlalchemy.orm import Session

from .config import get_settings
from .intel.common import utcnow
from .models import SyncState

# Keep in step with agent/src/posture.rs. Settings and policy keys only: no SAM or SECURITY
# hive, no user hives, no application data.
ALLOWED_KEYS = (
    "HKLM\\SOFTWARE\\Policies\\",
    "HKLM\\SOFTWARE\\Microsoft\\Policies\\",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\",
    "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\",
)
# Not registry: values the agent gets from a Windows API.
BUILTINS = ("wsc:antivirus", "wsc:firewall")
MAX_READS = 300
MAX_READ_LEN = 400

SEVERITIES = ("critical", "high", "medium", "low")
OPS = ("==", "!=", "<", "<=", ">", ">=", "exists", "missing")
Value = int | bool | Literal["set"] | None


def read_allowed(ref: str) -> bool:
    """A builtin, or a registry key (optionally ":value") inside ALLOWED_KEYS."""
    if ref in BUILTINS:
        return True
    if len(ref) > MAX_READ_LEN or "*" in ref or "/" in ref or "\\\\" in ref:
        return False
    key = ref.rsplit(":", 1)[0] if ":" in ref else ref
    k = key.upper() + "\\"
    return any(k.startswith(p.upper()) for p in ALLOWED_KEYS)


@dataclass(frozen=True)
class Condition:
    reads: tuple[str, ...]  # first one present wins
    op: str
    value: int | None = None
    default: int | None = None

    def holds(self, values: dict[str, Value]) -> bool:
        # "is not": a value of 0 equals False, but is a real setting.
        v = next((values[r] for r in self.reads if values.get(r) is not None and values.get(r) is not False), None)
        if self.op == "exists":
            return v is not None
        if self.op == "missing":
            return v is None
        if v is None:
            v = self.default
        if not isinstance(v, int) or isinstance(v, bool) or self.value is None:
            return False  # nothing set and no default, or a non-numeric value
        a, b = v, self.value
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[self.op]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    applies: str  # all | workstation | server
    fix: str
    why: str
    how: str
    when: tuple[Condition, ...]
    match: str = "all"
    reference: str | None = None
    # Only for Windows builds below this one, for settings whose default changed (TLS 1.0 and
    # 1.1 are off by default from build 26100, Windows 11 24H2 and Server 2025).
    before_build: int | None = None

    @property
    def reads(self) -> set[str]:
        return {r for c in self.when for r in c.reads}

    @property
    def fix_key(self) -> str:
        return f"posture:{self.id}"

    def applies_to(self, is_server: bool, build: int | None = None) -> bool:
        if self.before_build is not None and (build is None or build >= self.before_build):
            return False
        return self.applies == "all" or self.applies == ("server" if is_server else "workstation")


def build_number(os_build: str | None) -> int | None:
    """26100 from "10.0.26100.6899"."""
    parts = (os_build or "").split(".")
    return int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else None


@dataclass
class Ruleset:
    rules: list[Rule]
    reads: list[str] = field(default_factory=list)
    hash: str = ""

    def __post_init__(self):
        self.reads = sorted({r for rule in self.rules for r in rule.reads})
        # Only the reads go into the hash agents see: editing a title or a text needs no agent
        # round trip.
        self.hash = hashlib.sha256(json.dumps(self.reads).encode()).hexdigest()[:16]
        # Everything, for the server's own use: any change means findings must be re-judged.
        content = json.dumps([asdict(r) for r in self.rules], sort_keys=True)
        self.content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        self.by_id = {r.id: r for r in self.rules}


class RuleError(ValueError):
    pass


def _condition(rule_id: str, c: dict) -> Condition:
    reads = c.get("read")
    reads = (reads,) if isinstance(reads, str) else tuple(reads or ())
    if not reads:
        raise RuleError(f"{rule_id}: a condition has no read")
    for r in reads:
        if not read_allowed(r):
            raise RuleError(f"{rule_id}: {r!r} is outside what agents may read")
    op = c.get("op")
    if op not in OPS:
        raise RuleError(f"{rule_id}: unknown op {op!r}")
    if op not in ("exists", "missing") and not isinstance(c.get("value"), int):
        raise RuleError(f"{rule_id}: op {op!r} needs a whole-number value")
    if set(c) - {"read", "op", "value", "default"}:
        raise RuleError(f"{rule_id}: unknown condition fields {sorted(set(c) - {'read', 'op', 'value', 'default'})}")
    return Condition(reads=reads, op=op, value=c.get("value"), default=c.get("default"))


def parse(text: str) -> Ruleset:
    data = tomllib.loads(text)
    rules, seen = [], set()
    for r in data.get("rule", []):
        rid = r.get("id", "")
        if not rid or len(rid) > 32 or not all(ch.isalnum() or ch == "-" for ch in rid) or rid != rid.lower():
            raise RuleError(f"rule id {rid!r} must be 1 to 32 lowercase letters, digits or dashes")
        if rid in seen:
            raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        for k in ("title", "category", "fix", "why", "how"):
            if not isinstance(r.get(k), str) or not r[k].strip():
                raise RuleError(f"{rid}: {k} is required")
        if r.get("severity") not in SEVERITIES:
            raise RuleError(f"{rid}: severity must be one of {SEVERITIES}")
        if r.get("applies", "all") not in ("all", "workstation", "server"):
            raise RuleError(f"{rid}: applies must be all, workstation or server")
        if r.get("match", "all") not in ("all", "any"):
            raise RuleError(f"{rid}: match must be all or any")
        when = tuple(_condition(rid, c) for c in r.get("when", []))
        if not when:
            raise RuleError(f"{rid}: needs at least one condition")
        before = r.get("before_build")
        if before is not None and (not isinstance(before, int) or isinstance(before, bool) or before <= 0):
            raise RuleError(f"{rid}: before_build must be a Windows build number like 26100")
        rules.append(Rule(id=rid, title=r["title"].strip(), category=r["category"].strip(), severity=r["severity"],
                          applies=r.get("applies", "all"), fix=r["fix"].strip()[:400], why=r["why"].strip(), how=r["how"].strip(),
                          when=when, match=r.get("match", "all"), reference=r.get("reference"), before_build=before))
    rs = Ruleset(rules)
    if len(rs.reads) > MAX_READS:
        raise RuleError(f"{len(rs.reads)} reads; agents accept at most {MAX_READS}")
    return rs


@lru_cache
def ruleset(path: Path | None = None) -> Ruleset:
    return parse((path or get_settings().posture_rules_path).read_text(encoding="utf-8"))


def rule(rule_id: str) -> Rule | None:
    return ruleset().by_id.get(rule_id)


SYNC_KEY = "posture_rules"


def rematch_if_changed(s: Session) -> int:
    """Queue every device for re-evaluation when the rules differ from the ones findings were
    last judged by (a deploy changed a condition, a severity or a text). A rule change that
    keeps the same reads never reaches agents, so nothing else would refresh those findings.
    Returns the number of devices queued."""
    from .findings import mark_all_for_rematch  # findings imports this module

    rs, now = ruleset(), utcnow()
    st = s.get(SyncState, SYNC_KEY)
    if st is not None and st.cursor == rs.content_hash:
        return 0
    if st is None:
        st = SyncState(source=SYNC_KEY)
        s.add(st)
    st.cursor, st.last_started, st.last_success, st.last_status, st.rows = rs.content_hash, now, now, "ok", len(rs.rules)
    return mark_all_for_rematch(s)


@dataclass(frozen=True)
class Result:
    rule: Rule
    status: str  # fail | pass | unknown (the agent did not read every value this rule needs)


def evaluate(rs: Ruleset, values: dict[str, Value], is_server: bool, build: int | None = None) -> list[Result]:
    """`build`: the Windows build number (posture.build_number). Rules with before_build are
    skipped when it is unknown."""
    out = []
    for r in rs.rules:
        if not r.applies_to(is_server, build):
            continue
        if not r.reads <= values.keys():
            out.append(Result(r, "unknown"))
            continue
        hits = [c.holds(values) for c in r.when]
        failed = any(hits) if r.match == "any" else all(hits)
        out.append(Result(r, "fail" if failed else "pass"))
    return out
