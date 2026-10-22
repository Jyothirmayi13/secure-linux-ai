"""Declarative operator policy for the security boundary.

A policy file can only ever TIGHTEN the gateway. The deny-by-default floor in
risk_engine.py is not configurable, so a mistake in ``policy.yaml`` cannot open
a hole: an invalid, unreadable, unknown-key-containing, or baseline-weakening
policy raises PolicyError and callers must fail closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

POLICY_VERSION = 1

# Executables the baseline refuses no matter what policy.yaml says. Kept here as
# a second, independent list so a regex typo in risk_engine cannot silently
# widen the boundary; test T24 asserts the two agree.
PROTECTED_EXECUTABLES = frozenset({
    "rm", "rmdir", "unlink", "shred", "mkfs", "fdisk", "parted", "wipefs",
    "dd", "shutdown", "reboot", "poweroff", "halt", "init", "telinit",
    "kill", "killall", "pkill", "userdel", "groupdel", "chmod", "chown",
    "chattr", "mount", "umount", "systemctl", "service", "iptables", "nft",
    "ufw", "sudo", "su", "doas", "curl", "wget", "nc", "ncat", "socat",
    "sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "source",
    "python", "python3", "perl", "ruby", "node", "php", "lua",
})

# Credential-bearing locations that stay denied even if an operator rewrites
# read_roots to "/" .
BASELINE_DENY_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/.ssh/",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    ".env",
    "/proc/kcore",
    "/proc/sysrq-trigger",
)

BASELINE_READ_ROOTS = ("/var/log", "/etc", "/home", "/tmp", ".")

# Providers this build knows. providers.py keeps its own copy of this list and
# a test asserts the two agree, for the same reason PROTECTED_EXECUTABLES does:
# the policy parser must not accept a provider name nothing can satisfy.
AI_PROVIDER_NAMES = ("gemini", "openai", "ollama")

# Approval modes this build understands. approval.py keeps its own copy of
# these numbers and a test asserts the two agree, for the same reason
# AI_PROVIDER_NAMES does: the parser must not accept a setting nothing honours.
# "off" is absent on purpose - the built-in floor already requires a signed
# human approval, so a policy file may tighten that but never remove it.
APPROVAL_MODE_NAMES = ("interactive", "strict")
APPROVAL_DEFAULT_TTL_SECONDS = 120
APPROVAL_FLOOR_MAX_TTL_SECONDS = 900


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern
    reason: str


@dataclass(frozen=True)
class Policy:
    name: str = "builtin"
    source: str = "builtin"
    allow_executables: frozenset[str] = frozenset()
    deny_executables: frozenset[str] = frozenset()
    deny_paths: tuple[str, ...] = BASELINE_DENY_PATHS
    deny_arguments: frozenset[str] = frozenset()
    rules: tuple[Rule, ...] = ()
    injection_rules: tuple[Rule, ...] = ()
    max_score: int = 100
    block_sensitive: bool = False
    read_roots: tuple[str, ...] = BASELINE_READ_ROOTS
    tech_enabled: bool = True
    max_suggestions: int = 5
    ai_provider: str = ""
    ai_model: str = ""
    ai_base_url: str = ""
    ai_allow_cloud: bool = True
    approval_mode: str = "interactive"
    approval_ttl: int = APPROVAL_DEFAULT_TTL_SECONDS

    @property
    def source_label(self) -> str:
        return (
            "built-in floor"
            if self.source == "builtin"
            else Path(self.source).name
        )

    @property
    def effective_deny_paths(self) -> tuple[str, ...]:
        return BASELINE_DENY_PATHS + tuple(
            p for p in self.deny_paths if p not in BASELINE_DENY_PATHS
        )

    def allowed_executable(self, name: str) -> bool:
        return name.lower() in self.allow_executables

    def is_denied_executable(self, name: str) -> bool:
        return name.lower() in self.deny_executables

    def describe(self) -> list[tuple[str, str, str]]:
        """Rows of (setting, value, origin) for --policy-show."""
        from_file = self.source != "builtin"

        def origin(used: bool) -> str:
            return self.source_label if (used and from_file) else "built-in floor"

        extra_paths = [
            p for p in self.deny_paths if p not in BASELINE_DENY_PATHS
        ]
        return [
            ("policy name", self.name, self.source_label),
            ("read-only allow-list additions",
             ", ".join(sorted(self.allow_executables)) or "(none)",
             origin(bool(self.allow_executables))),
            ("extra denied executables",
             ", ".join(sorted(self.deny_executables)) or "(none)",
             origin(bool(self.deny_executables))),
            ("extra denied paths",
             ", ".join(extra_paths) or "(none)",
             origin(bool(extra_paths))),
            ("always denied paths", ", ".join(BASELINE_DENY_PATHS), "built-in floor"),
            ("extra denied arguments",
             ", ".join(sorted(self.deny_arguments)) or "(none)",
             origin(bool(self.deny_arguments))),
            ("custom rules",
             ", ".join(r.rule_id for r in self.rules) or "(none)",
             origin(bool(self.rules))),
            ("extra injection patterns",
             ", ".join(r.rule_id for r in self.injection_rules) or "(none)",
             origin(bool(self.injection_rules))),
            ("maximum allowed risk score", str(self.max_score),
             origin(self.max_score != 100)),
            ("block HIGH instead of asking", str(self.block_sensitive),
             origin(self.block_sensitive)),
            ("diagnostic tool read roots",
             ", ".join(self.read_roots), origin(from_file)),
            ("tech mode enabled", str(self.tech_enabled),
             origin(not self.tech_enabled)),
            ("tech mode max suggestions", str(self.max_suggestions),
             origin(self.max_suggestions != 5)),
            ("AI provider pinned", self.ai_provider or
             "(not pinned: chosen from the environment)",
             origin(bool(self.ai_provider))),
            ("AI model pinned", self.ai_model or "(not pinned)",
             origin(bool(self.ai_model))),
            ("AI endpoint pinned", self.ai_base_url or "(provider default)",
             origin(bool(self.ai_base_url))),
            ("AI may send data off this machine", str(self.ai_allow_cloud),
             origin(not self.ai_allow_cloud)),
            ("approval artefact required", self.approval_mode,
             origin(self.approval_mode != "interactive")),
            ("approval token lifetime",
             f"{self.approval_ttl}s, ceiling "
             f"{APPROVAL_FLOOR_MAX_TTL_SECONDS}s is not configurable",
             origin(self.approval_ttl != APPROVAL_DEFAULT_TTL_SECONDS)),
        ]


_SCHEMA_KEYS = frozenset({
    "version", "name", "allow_executables", "deny_executables", "deny_paths",
    "deny_arguments", "rules", "injection_patterns", "max_score",
    "block_sensitive", "read_roots", "tech_mode", "ai", "approval",
})

_RULE_KEYS = frozenset({"id", "pattern", "reason"})

_AI_KEYS = frozenset({"provider", "model", "base_url", "allow_cloud"})

_APPROVAL_KEYS = frozenset({"mode", "ttl_seconds"})

# http(s) only, and no userinfo: a URL that carries a user:password@ section is
# not something an operator should be pinning as a model endpoint.
_URL_SHAPE = re.compile(r"^https?://[^\s@/][^\s@]*$", re.IGNORECASE)


class PolicyError(Exception):
    """Raised for any policy problem. Callers must fail closed."""


def _string_list(value: Any, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise PolicyError(
            f"'{key}' must be a list of non-empty strings"
        )
    return tuple(item.strip() for item in value)


def _compile(pattern: str, rule_id: str) -> re.Pattern:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise PolicyError(
            f"rule '{rule_id}' has an invalid regular expression: {exc}"
        ) from exc


def load_policy(path: str | Path) -> Policy:
    """Parse and validate a policy file. Raises PolicyError on any problem."""
    file_path = Path(path).expanduser()

    if not file_path.is_file():
        raise PolicyError(f"policy file not found: {file_path}")

    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"policy file is unreadable: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        where = f" (line {line + 1})" if line is not None else ""
        raise PolicyError(f"policy file is not valid YAML{where}: {exc}") from exc

    if raw is None:
        raise PolicyError("policy file is empty")
    if not isinstance(raw, dict):
        raise PolicyError("policy file must contain a mapping of settings")

    unknown = set(raw) - _SCHEMA_KEYS
    if unknown:
        raise PolicyError(
            "unknown policy setting(s): "
            f"{', '.join(sorted(unknown))}. Refusing to guess."
        )

    version = raw.get("version", POLICY_VERSION)
    if version != POLICY_VERSION:
        raise PolicyError(
            f"unsupported policy version {version!r}; this build reads "
            f"version {POLICY_VERSION}"
        )

    policy = DEFAULT_POLICY
    name = raw.get("name", Path(file_path).stem)
    if not isinstance(name, str) or not name.strip():
        raise PolicyError("'name' must be a non-empty string")
    policy = replace(policy, name=name.strip(), source=str(file_path))

    # --- executables -----------------------------------------------------
    if "allow_executables" in raw:
        additions = _string_list(raw["allow_executables"], "allow_executables")
        protected = [a for a in additions if a.lower() in PROTECTED_EXECUTABLES]
        if protected:
            raise PolicyError(
                "cannot allow protected baseline executable(s): "
                f"{', '.join(protected)}. The deny-by-default floor is not "
                "configurable."
            )
        policy = replace(
            policy,
            allow_executables=policy.allow_executables
            | frozenset(a.lower() for a in additions),
        )

    if "deny_executables" in raw:
        denied = _string_list(raw["deny_executables"], "deny_executables")
        policy = replace(
            policy,
            deny_executables=policy.deny_executables
            | frozenset(d.lower() for d in denied),
        )

    # --- paths and arguments --------------------------------------------
    if "deny_paths" in raw:
        extra = _string_list(raw["deny_paths"], "deny_paths")
        policy = replace(policy, deny_paths=policy.deny_paths + extra)

    if "deny_arguments" in raw:
        extra = _string_list(raw["deny_arguments"], "deny_arguments")
        policy = replace(
            policy,
            deny_arguments=policy.deny_arguments | frozenset(extra),
        )

    # --- custom rules ----------------------------------------------------
    if "rules" in raw:
        policy = replace(policy, rules=_build_rules(raw["rules"], "rules"))

    if "injection_patterns" in raw:
        policy = replace(
            policy,
            injection_rules=_build_rules(
                raw["injection_patterns"], "injection_patterns"
            ),
        )

    # --- thresholds ------------------------------------------------------
    if "max_score" in raw:
        score = raw["max_score"]
        if type(score) is not int or not 0 <= score <= 100:
            raise PolicyError("'max_score' must be an integer from 0 to 100")
        if score > policy.max_score:
            raise PolicyError(
                f"'max_score' {score} would loosen the builtin limit "
                f"{policy.max_score}; a policy may only tighten."
            )
        policy = replace(policy, max_score=score)

    if "block_sensitive" in raw:
        value = raw["block_sensitive"]
        if not isinstance(value, bool):
            raise PolicyError("'block_sensitive' must be true or false")
        policy = replace(policy, block_sensitive=value)

    # --- diagnostic tool scope ------------------------------------------
    if "read_roots" in raw:
        roots = _string_list(raw["read_roots"], "read_roots")
        if not roots:
            raise PolicyError(
                "'read_roots' cannot be empty; it replaces the builtin "
                "list, so leaving it blank would make every path readable."
            )
        policy = replace(policy, read_roots=roots)

    if "tech_mode" in raw:
        section = raw["tech_mode"]
        if not isinstance(section, dict):
            raise PolicyError("'tech_mode' must be a mapping")
        unknown = set(section) - {"enabled", "max_suggestions"}
        if unknown:
            raise PolicyError(
                "unknown tech_mode setting(s): "
                f"{', '.join(sorted(unknown))}"
            )
        if "enabled" in section:
            if not isinstance(section["enabled"], bool):
                raise PolicyError("tech_mode.enabled must be true or false")
            policy = replace(policy, tech_enabled=section["enabled"])
        if "max_suggestions" in section:
            value = section["max_suggestions"]
            if type(value) is not int or not 1 <= value <= DEFAULT_POLICY.max_suggestions:
                raise PolicyError(
                    "tech_mode.max_suggestions must be an integer from 1 to "
                    f"{DEFAULT_POLICY.max_suggestions}"
                )
            policy = replace(policy, max_suggestions=value)

    # --- AI provider and egress ------------------------------------------
    # The model endpoint is part of this boundary: a diagnosis ships the
    # operator's question and the contents of local files to whoever answers.
    if "ai" in raw:
        policy = replace(policy, **_build_ai(raw["ai"]))

    # --- approval artefacts ----------------------------------------------
    if "approval" in raw:
        policy = replace(policy, **_build_approval(raw["approval"]))

    return policy


def _build_approval(value: Any) -> dict[str, Any]:
    """Validate the ``approval:`` policy section. Returns keyword overrides."""
    if not isinstance(value, dict):
        raise PolicyError("'approval' must be a mapping of settings")

    unknown = set(value) - _APPROVAL_KEYS
    if unknown:
        raise PolicyError(
            f"unknown approval setting(s): {', '.join(sorted(unknown))}. "
            "Refusing to guess."
        )

    updates: dict[str, Any] = {}

    if "mode" in value:
        mode = value["mode"]
        if not isinstance(mode, str) or not mode.strip():
            raise PolicyError("approval.mode must be a non-empty string")
        mode = mode.strip().lower()
        if mode == "off":
            raise PolicyError(
                "approval.mode cannot be 'off'. The built-in floor requires "
                "every execution to carry a signed, single-use human "
                "approval; a policy file may only ask for more of that, not "
                "less. Use 'interactive' or 'strict'."
            )
        if mode not in APPROVAL_MODE_NAMES:
            raise PolicyError(
                f"approval.mode must be one of {', '.join(APPROVAL_MODE_NAMES)}; "
                f"got {mode!r}"
            )
        updates["approval_mode"] = mode

    if "ttl_seconds" in value:
        ttl = value["ttl_seconds"]
        if type(ttl) is not int or not 1 <= ttl <= APPROVAL_DEFAULT_TTL_SECONDS:
            raise PolicyError(
                "approval.ttl_seconds must be an integer from 1 to "
                f"{APPROVAL_DEFAULT_TTL_SECONDS}; a policy may shorten an "
                "approval's life but never lengthen it"
            )
        updates["approval_ttl"] = ttl

    return updates


def _build_ai(value: Any) -> dict[str, Any]:
    """Validate the ``ai:`` policy section. Returns keyword overrides."""
    if not isinstance(value, dict):
        raise PolicyError("'ai' must be a mapping of settings")

    unknown = set(value) - _AI_KEYS
    if unknown:
        raise PolicyError(
            f"unknown ai setting(s): {', '.join(sorted(unknown))}. "
            "Refusing to guess."
        )

    updates: dict[str, Any] = {}

    if "provider" in value:
        provider = value["provider"]
        if not isinstance(provider, str) or not provider.strip():
            raise PolicyError("ai.provider must be a non-empty string")
        provider = provider.strip().lower()
        if provider not in AI_PROVIDER_NAMES:
            raise PolicyError(
                f"ai.provider must be one of {', '.join(AI_PROVIDER_NAMES)}; "
                f"got {provider!r}"
            )
        updates["ai_provider"] = provider

    if "model" in value:
        model = value["model"]
        if not isinstance(model, str) or not model.strip():
            raise PolicyError("ai.model must be a non-empty string")
        model = model.strip()
        if any(char.isspace() for char in model):
            raise PolicyError("ai.model cannot contain spaces")
        updates["ai_model"] = model

    if "base_url" in value:
        url = value["base_url"]
        if not isinstance(url, str) or not url.strip():
            raise PolicyError("ai.base_url must be a non-empty string")
        url = url.strip()
        if not _URL_SHAPE.match(url):
            raise PolicyError(
                "ai.base_url must be an http(s) URL without credentials, "
                f"got {url!r}"
            )
        updates["ai_base_url"] = url

    if "allow_cloud" in value:
        allow = value["allow_cloud"]
        if not isinstance(allow, bool):
            raise PolicyError("ai.allow_cloud must be true or false")
        updates["ai_allow_cloud"] = allow

    # A policy that pins a remote endpoint and forbids cloud egress is asking
    # for two opposite things; reject it here rather than at the first query.
    url = updates.get("ai_base_url", "")
    if updates.get("ai_allow_cloud") is False and url:
        # Imported lazily: providers.py imports this module at load time.
        from providers import is_loopback

        if not is_loopback(url):
            raise PolicyError(
                "ai.base_url points away from this machine while "
                "ai.allow_cloud is false. Refusing to load a policy that "
                "contradicts itself."
            )

    return updates


def _build_rules(value: Any, key: str) -> tuple[Rule, ...]:
    if not isinstance(value, list):
        raise PolicyError(f"'{key}' must be a list of rules")

    rules: list[Rule] = []
    seen: set[str] = set()

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise PolicyError(f"{key}[{index}] must be a mapping")
        unknown = set(item) - _RULE_KEYS
        if unknown:
            raise PolicyError(
                f"unknown key(s) in {key}[{index}]: {', '.join(sorted(unknown))}"
            )

        rule_id = str(item.get("id") or f"{key}[{index}]").strip()
        if rule_id in seen:
            raise PolicyError(f"duplicate rule id '{rule_id}' in '{key}'")
        seen.add(rule_id)

        pattern = item.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            raise PolicyError(f"rule '{rule_id}' needs a non-empty 'pattern'")

        reason = item.get("reason", "matched operator rule")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"rule '{rule_id}' has an invalid 'reason'")

        rules.append(Rule(rule_id, _compile(pattern, rule_id), reason.strip()))

    return tuple(rules)


def discover_policy(start: str | Path | None = None) -> Path | None:
    """Find policy.yaml next to the code, then in the working directory."""
    candidates: list[Path] = []

    if start:
        candidates.append(Path(start))
    candidates.append(Path(__file__).resolve().parent / "policy.yaml")
    candidates.append(Path.cwd() / "policy.yaml")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


DEFAULT_POLICY = Policy()
