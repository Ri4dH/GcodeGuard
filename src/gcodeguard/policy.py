"""Policy model, YAML loading, inheritance, and strict validation.

Policies are safety configuration, so typos must fail loudly: unknown keys,
wrong types, and impossible ranges all raise :class:`PolicyError`.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from gcodeguard.model import Action, Severity

_BUILTIN_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed, or unsafe."""


@dataclass(frozen=True)
class Range:
    low: float
    high: float

    def contains(self, value: float, margin: float = 0.0) -> bool:
        return self.low - margin <= value <= self.high + margin


@dataclass(frozen=True)
class Machine:
    firmware: str = "marlin"  # marlin | klipper | reprap
    build_volume: Mapping[str, Range] = field(
        default_factory=lambda: {"X": Range(0, 220), "Y": Range(0, 220), "Z": Range(0, 250)}
    )
    bounds_margin_mm: float = 2.0
    max_hotend_temp: float = 260.0
    max_bed_temp: float = 110.0
    max_chamber_temp: float = 60.0
    min_print_temp: float = 170.0
    max_feedrate_mm_s: float = 300.0
    max_accel_mm_s2: float = 10000.0
    nozzle_diameter: float = 0.4
    filament_diameter: float = 1.75
    max_layer_height_mm: float = 0.32


@dataclass(frozen=True)
class Thermal:
    heater_idle_timeout_s: float = 600.0
    max_dwell_s: float = 300.0
    max_temp_drop_c: float = 25.0
    idle_heater_threshold_c: float = 50.0


@dataclass(frozen=True)
class Sabotage:
    flow_percent: Range = Range(90, 110)
    speed_percent: Range = Range(50, 150)
    extrusion_window: int = 60
    extrusion_low_ratio: float = 0.55
    extrusion_high_ratio: float = 4.0  # bridges legitimately run ~3x
    extrusion_min_run_mm: float = 25.0
    layer_low_ratio: float = 0.7
    layer_high_ratio: float = 3.5


@dataclass(frozen=True)
class RuleConfig:
    enabled: bool = True
    severity: Severity | None = None
    action: Action | None = None


@dataclass(frozen=True)
class Commands:
    allow: frozenset[str] = frozenset()
    block: frozenset[str] = frozenset()
    unknown: Action = Action.WARN


@dataclass(frozen=True)
class Policy:
    name: str = "default"
    description: str = ""
    mode: str = "enforce"  # enforce | monitor
    machine: Machine = field(default_factory=Machine)
    thermal: Thermal = field(default_factory=Thermal)
    sabotage: Sabotage = field(default_factory=Sabotage)
    actions: Mapping[Severity, Action] = field(
        default_factory=lambda: {
            Severity.INFO: Action.ALLOW,
            Severity.WARNING: Action.WARN,
            Severity.CRITICAL: Action.BLOCK,
        }
    )
    rules: Mapping[str, RuleConfig] = field(default_factory=dict)
    commands: Commands = field(default_factory=Commands)

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def rule(self, rule_id: str) -> RuleConfig:
        return self.rules.get(rule_id, _DEFAULT_RULE)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        return _build_policy(data)


_DEFAULT_RULE = RuleConfig()

# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def builtin_profiles() -> list[str]:
    root = resources.files("gcodeguard") / "profiles"
    return sorted(p.name[:-5] for p in root.iterdir() if p.name.endswith(".yaml"))


def _read_builtin(name: str) -> dict[str, Any]:
    if not _BUILTIN_NAME.match(name):
        raise PolicyError(f"invalid built-in profile name {name!r}")
    path = resources.files("gcodeguard") / "profiles" / f"{name}.yaml"
    if not path.is_file():
        available = ", ".join(builtin_profiles())
        raise PolicyError(f"unknown profile {name!r} (available: {available})")
    return _parse_yaml(path.read_text(encoding="utf-8"), f"profile:{name}")


def _read_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    return _parse_yaml(text, str(path))


def _parse_yaml(text: str, origin: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"{origin}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{origin}: policy must be a mapping")
    return data


def _looks_like_path(ref: str) -> bool:
    return ref.endswith((".yaml", ".yml")) or "/" in ref or "\\" in ref


def _resolve(ref: str, base_dir: Path | None, seen: tuple[str, ...]) -> dict[str, Any]:
    if _looks_like_path(ref):
        path = Path(ref).expanduser()
        if not path.is_absolute() and base_dir is not None:
            path = base_dir / path
        key = str(path.resolve())
        data = _read_file(path)
        next_base = path.parent
    else:
        key = f"builtin:{ref}"
        data = _read_builtin(ref)
        next_base = None
    if key in seen:
        raise PolicyError(f"policy inheritance cycle: {' -> '.join(seen + (key,))}")
    parent = data.pop("extends", None)
    if parent is None:
        return data
    if not isinstance(parent, str):
        raise PolicyError(f"{ref}: 'extends' must be a string")
    return merge(_resolve(parent, next_base, seen + (key,)), data)


def merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-merge two raw policy dicts. ``commands.allow``/``block`` are unioned."""
    out = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = merge(out[key], value)
        elif key in {"allow", "block"} and isinstance(value, list) and isinstance(out.get(key), list):
            out[key] = sorted(set(out[key]) | set(value))
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_policy(*refs: str | Path) -> Policy:
    """Load and merge one or more policies (built-in names or YAML paths), left to right."""
    if not refs:
        refs = ("generic-fdm",)
    merged: dict[str, Any] = {}
    names: list[str] = []
    for ref in refs:
        data = _resolve(str(ref), None, ())
        names.append(str(data.get("name", ref)))
        merged = merge(merged, data)
    merged["name"] = " + ".join(names) if len(names) > 1 else names[0]
    return _build_policy(merged)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_TOP_KEYS = {"name", "description", "mode", "machine", "thermal", "sabotage", "actions", "rules", "commands"}


def _check_keys(section: str, data: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{section}: unknown key(s) {sorted(unknown)}; allowed: {sorted(allowed)}")


def _number(section: str, key: str, value: Any, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"{section}.{key}: expected a number, got {value!r}")
    if value < minimum:
        raise PolicyError(f"{section}.{key}: must be >= {minimum}, got {value}")
    return float(value)


def _range(section: str, key: str, value: Any) -> Range:
    if not (isinstance(value, (list, tuple)) and len(value) == 2):
        raise PolicyError(f"{section}.{key}: expected [low, high], got {value!r}")
    low = _number(section, key, value[0], minimum=-1e9)
    high = _number(section, key, value[1], minimum=-1e9)
    if low > high:
        raise PolicyError(f"{section}.{key}: low {low} is greater than high {high}")
    return Range(low, high)


def _enum(section: str, enum_cls: type, value: Any) -> Any:
    try:
        return enum_cls(str(value).lower())
    except ValueError:
        options = [e.value for e in enum_cls]
        raise PolicyError(f"{section}: {value!r} is not one of {options}") from None


def _build_dataclass(cls: type, section: str, data: Any, ranges: set[str] = frozenset()) -> Any:
    if data is None:
        return cls()
    if not isinstance(data, Mapping):
        raise PolicyError(f"{section}: expected a mapping")
    defaults = cls()
    allowed = set(defaults.__dataclass_fields__)
    _check_keys(section, data, allowed)
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        current = getattr(defaults, key)
        if key in ranges:
            kwargs[key] = _range(section, key, value)
        elif isinstance(current, str):
            kwargs[key] = str(value)
        elif isinstance(current, int) and not isinstance(current, bool):
            kwargs[key] = int(_number(section, key, value, minimum=1))
        else:
            kwargs[key] = _number(section, key, value)
    return cls(**kwargs)


def _build_machine(data: Any) -> Machine:
    if data is None:
        return Machine()
    if not isinstance(data, Mapping):
        raise PolicyError("machine: expected a mapping")
    data = dict(data)
    volume = data.pop("build_volume", None)
    machine = _build_dataclass(Machine, "machine", data)
    if machine.firmware not in {"marlin", "klipper", "reprap"}:
        raise PolicyError(f"machine.firmware: unsupported firmware {machine.firmware!r}")
    if volume is None:
        return machine
    if not isinstance(volume, Mapping):
        raise PolicyError("machine.build_volume: expected a mapping of axis -> [min, max]")
    _check_keys("machine.build_volume", {k.lower(): v for k, v in volume.items()}, {"x", "y", "z"})
    axes = dict(machine.build_volume)
    for axis, bounds in volume.items():
        axes[axis.upper()] = _range("machine.build_volume", axis, bounds)
    return Machine(**{**machine.__dict__, "build_volume": axes})


def _build_rules(data: Any) -> dict[str, RuleConfig]:
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise PolicyError("rules: expected a mapping of rule-id -> settings")
    from gcodeguard.rules import RULE_IDS  # local import to avoid a cycle

    out: dict[str, RuleConfig] = {}
    for rule_id, cfg in data.items():
        if rule_id not in RULE_IDS:
            raise PolicyError(f"rules: unknown rule {rule_id!r}; known: {sorted(RULE_IDS)}")
        if cfg is False:
            out[rule_id] = RuleConfig(enabled=False)
            continue
        if not isinstance(cfg, Mapping):
            raise PolicyError(f"rules.{rule_id}: expected a mapping or false")
        _check_keys(f"rules.{rule_id}", cfg, {"enabled", "severity", "action"})
        out[rule_id] = RuleConfig(
            enabled=bool(cfg.get("enabled", True)),
            severity=_enum(f"rules.{rule_id}.severity", Severity, cfg["severity"]) if "severity" in cfg else None,
            action=_enum(f"rules.{rule_id}.action", Action, cfg["action"]) if "action" in cfg else None,
        )
    return out


def _build_commands(data: Any) -> Commands:
    if data is None:
        return Commands()
    if not isinstance(data, Mapping):
        raise PolicyError("commands: expected a mapping")
    _check_keys("commands", data, {"allow", "block", "unknown"})

    def codes(key: str) -> frozenset[str]:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise PolicyError(f"commands.{key}: expected a list of command names")
        return frozenset(v.strip().upper() for v in value)

    unknown = _enum("commands.unknown", Action, data.get("unknown", "warn"))
    if unknown is Action.CLAMP:
        raise PolicyError("commands.unknown: 'clamp' makes no sense for unknown commands")
    return Commands(allow=codes("allow"), block=codes("block"), unknown=unknown)


def _build_policy(data: Mapping[str, Any]) -> Policy:
    _check_keys("policy", data, _TOP_KEYS)
    mode = str(data.get("mode", "enforce")).lower()
    if mode not in {"enforce", "monitor"}:
        raise PolicyError(f"mode: must be 'enforce' or 'monitor', got {mode!r}")
    actions = dict(Policy().actions)
    raw_actions = data.get("actions") or {}
    if not isinstance(raw_actions, Mapping):
        raise PolicyError("actions: expected a mapping of severity -> action")
    for sev, act in raw_actions.items():
        actions[_enum("actions", Severity, sev)] = _enum(f"actions.{sev}", Action, act)
    return Policy(
        name=str(data.get("name", "custom")),
        description=str(data.get("description", "")),
        mode=mode,
        machine=_build_machine(data.get("machine")),
        thermal=_build_dataclass(Thermal, "thermal", data.get("thermal")),
        sabotage=_build_dataclass(
            Sabotage, "sabotage", data.get("sabotage"), ranges={"flow_percent", "speed_percent"}
        ),
        actions=actions,
        rules=_build_rules(data.get("rules")),
        commands=_build_commands(data.get("commands")),
    )
