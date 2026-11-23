#!/usr/bin/env python3
"""as-config: capture an OpenVPN Access Server configuration once, apply it anywhere.

Runs as root on the Access Server host or container. Uses only the Python 3
standard library and `sacli`.

Commands:
  baseline -o baseline.json                    save the fresh server's state
  export --baseline baseline.json -o FILE      write the differences to as-config.json
  validate FILE [--values staging.env]         check a file without changing anything
  apply FILE --values staging.env [--dry-run]  apply a file to this server
  rollback BACKUP_DIR                          restore a backup taken by apply

Findings behind the design are in FINDINGS.md next to this file.
"""

# Security check first, before any other import: Python searches the script's own directory for
# modules, so as root a json.py planted next to this file (in /tmp, say) would run as root.
# os and sys are already loaded when Python starts, so importing them here is safe.
import os
import sys

if __name__ == "__main__" and not sys.flags.isolated and os.geteuid() == 0:
    _here = os.path.dirname(os.path.abspath(sys.argv[0]))
    _st = os.stat(_here)
    _owners = {0, int(os.environ.get("SUDO_UID", "0") or 0)}   # root, or the admin who ran sudo
    if _st.st_mode & 0o022 or _st.st_uid not in _owners:
        sys.stderr.write(
            f"as_config.py: refusing to run as root from {_here}: other users can write there and could "
            "plant Python modules that would run as root. Copy as_config.py to a private directory "
            "(for example: install -d -m 700 ~/as-config), or run it with python3 -I.\n")
        sys.exit(1)

import argparse
import copy
import datetime
import fcntl
import hashlib
import json
import re
import secrets as pysecrets
import shutil
import subprocess
import tempfile
import time

TOOL_VERSION = "1.2.0"
FORMAT = 1
DEFAULT_STATE_DIR = "/var/lib/as-config"
SACLI_CANDIDATES = ("/usr/local/openvpn_as/scripts/sacli", "sacli")

# --------------------------------------------------------------------------
# Keys and properties the tool never exports or writes (FINDINGS.md, Q5/Q6).
# --------------------------------------------------------------------------
PROTECTED_EXACT = {
    "host.name",
    "auth.sessiontoken.secretkey",
    "vpn.server.daemon.tcp.n_daemons",
    "vpn.server.daemon.udp.n_daemons",
    "acme.node",
    "acme.sni",
    "node_type",
    "cs.cert",
    "cs.priv_key",
    "cs.ca_bundle",
}
PROTECTED_PREFIXES = (
    "subscription.",
    "upgrade.",
    "acme.internal.",
    "extip.polling_service.internal.",
    "cluster.",
    "dbpush.",
)
# Keys ConfigReplace re-inserts when they are missing (Q3). Unsetting them cannot work.
REINSERTED = {
    "auth.local.0.enable",
    "auth.module.type",
    "auth.sessiontoken.secretkey",
    "upgrade.current_version",
    "upgrade.initial_version",
    "vpn.server.tls_cc_security",
}
# Last key segment that marks a value as a secret (decision 3). Anchored at the end so that
# settings such as acme.api_key_algorithm or names containing "bypass" are not caught.
SECRET_SEGMENT = re.compile(r"(^|_)(pass|passwd|password|passphrase|pw|pwd|secret|secretkey|token|key|credentials?)$", re.I)

OWNER_TYPES_USER = ("user_connect", "user_compile")
DEFAULT_OWNER = "__DEFAULT__"
RULE_FIELDS = ("type", "match_type", "match_data", "action", "comment")
VAR_RE = re.compile(r"\$(\$)?\{([A-Za-z_][A-Za-z0-9_]*)\}")
IP_LIKE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?\b")

# --------------------------------------------------------------------------
# JSON Schema for as-config.json format 1. `as_config.py schema` prints it;
# schema/as-config.schema.json is generated from it.
# --------------------------------------------------------------------------
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "as-config.schema.json",
    "title": "Access Server configuration file (as-config.json), format 1",
    "description": "Differences from a fresh Access Server, plus groups, users, Domain Routing rulesets and policies. "
                   "String values may contain ${NAME} references to entries in `variables` or `secrets`; write $${ for a literal ${.",
    "type": "object",
    "required": ["format", "access_server_version", "config"],
    "additionalProperties": False,
    "properties": {
        "format": {"const": 1},
        "access_server_version": {"type": "string", "pattern": r"^[0-9]+\.[0-9]+(\.[0-9]+)?$"},
        "generated_by": {"type": "string"},
        "config": {
            "type": "object",
            "required": ["set", "unset"],
            "additionalProperties": False,
            "properties": {
                "set": {"type": "object", "additionalProperties": {"type": "string"}},
                "unset": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
            },
        },
        "groups": {
            "description": "Groups to create or update. Groups on the server that are missing from this map are kept "
                           "(apply prints a warning) unless apply --prune-groups is given. "
                           "The key __DEFAULT__ holds the user-defaults record; it is updated, never deleted.",
            "type": "object",
            "additionalProperties": {"$ref": "#/$defs/owner"},
        },
        "users": {
            "description": "Users to create or update. New local users get a random temporary password. "
                           "Users missing from this map are kept unless apply --prune-users is given; superusers are never deleted.",
            "type": "object",
            "propertyNames": {"not": {"const": "__DEFAULT__"}},
            "additionalProperties": {"$ref": "#/$defs/owner"},
        },
        "rulesets": {
            "description": "Domain Routing rulesets to create or update, by name. Rulesets on the server that are missing "
                           "from this map are kept (and stay assigned) unless apply --prune-rulesets is given.",
            "type": "object",
            "additionalProperties": {"$ref": "#/$defs/ruleset"},
        },
        "policies": {
            "description": "Policies to create or replace, matched by name. Policies on the server that are missing from "
                           "this list are kept unless apply --prune-policies is given. Omit the key to leave policies alone.",
            "type": "array",
            "items": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "minLength": 1}}},
        },
        "variables": {"type": "array", "items": {"$ref": "#/$defs/name"}, "uniqueItems": True},
        "secrets": {"type": "array", "items": {"$ref": "#/$defs/name"}, "uniqueItems": True},
    },
    "$defs": {
        "name": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
        "owner": {
            "description": "User properties as sacli UserPropPut keys. access_to.N is written as the list access_to; "
                           "rulesets lists Domain Routing rulesets by name, in priority order.",
            "type": "object",
            "properties": {
                "access_to": {"type": "array", "items": {"type": "string"}},
                "rulesets": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
            },
            "propertyNames": {"not": {"pattern": r"^(pvt_|type$|access_to\.)"}},
            "additionalProperties": {"type": "string"},
        },
        "ruleset": {
            "type": "object",
            "required": ["rules"],
            "additionalProperties": False,
            "properties": {
                "comment": {"type": "string"},
                "rules": {"type": "array", "items": {"$ref": "#/$defs/rule"}},
            },
        },
        "rule": {
            "description": "One rule; its position is its index in the list plus one.",
            "type": "object",
            "required": ["type", "match_type", "match_data", "action"],
            "additionalProperties": False,
            "properties": {
                "type": {"enum": ["domain_routing", "filter"]},
                "match_type": {"enum": ["domain", "not_domain", "subdomain", "not_subdomain",
                                        "domain_or_subdomain", "not_domain_or_subdomain"]},
                "match_data": {"type": "string"},
                "action": {"enum": ["route", "nat", "deny", "bypass"]},
                "comment": {"type": "string"},
            },
        },
    },
}


class Fail(Exception):
    """A refusal or error that ends the command with a message."""

    def __init__(self, msg, code=1):
        super().__init__(msg)
        self.code = code


REDACT = set()   # secret values that must never be printed (filled by apply and rollback)


def redact(text):
    """Replace every known secret value in text with <secret>. Server error messages can echo
    the values they reject (FINDINGS Q4), so all output goes through here."""
    text = str(text)
    for value in sorted(REDACT, key=len, reverse=True):
        text = text.replace(value, "<secret>")
    return text


def remember_secrets(snap):
    """Register secret values held by a snapshot: secret-looking config keys, the session key,
    subscription state and pvt_* properties (password hashes, TOTP secrets)."""
    for k, v in snap.get("config", {}).items():
        if is_secret_key(k) or k == "auth.sessiontoken.secretkey" or k.startswith("subscription."):
            add_secret(v)
    for props in snap.get("userprops", {}).values():
        for k, v in props.items():
            if k.startswith("pvt_") or is_secret_key(k):
                add_secret(v)


def add_secret(value):
    # Very short values would blank out ordinary words and numbers in messages.
    if isinstance(value, str) and len(value) >= 6:
        REDACT.add(value)


def log(msg=""):
    print(redact(msg), file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Small JSON Schema validator (the subset SCHEMA uses).
# --------------------------------------------------------------------------
def schema_errors(inst, schema=SCHEMA, path="$", root=SCHEMA):
    errs = []
    if "$ref" in schema:
        ref = schema["$ref"]
        node = root
        for part in ref.lstrip("#/").split("/"):
            node = node[part]
        return schema_errors(inst, node, path, root)
    if "not" in schema and not schema_errors(inst, schema["not"], path, root):
        errs.append(f"{path}: value {inst!r} is not allowed")
    if "const" in schema and inst != schema["const"]:
        errs.append(f"{path}: must be {schema['const']!r}")
    if "enum" in schema and inst not in schema["enum"]:
        errs.append(f"{path}: must be one of {schema['enum']}")
    t = schema.get("type")
    types = {"object": dict, "array": list, "string": str}
    if t and not isinstance(inst, types[t]):
        return errs + [f"{path}: must be {t}, got {type(inst).__name__}"]
    if isinstance(inst, str):
        if "pattern" in schema and not re.search(schema["pattern"], inst):
            errs.append(f"{path}: {inst!r} does not match {schema['pattern']}")
        if len(inst) < schema.get("minLength", 0):
            errs.append(f"{path}: must not be empty")
    if isinstance(inst, list):
        if schema.get("uniqueItems") and len({json.dumps(i, sort_keys=True) for i in inst}) != len(inst):
            errs.append(f"{path}: items must be unique")
        if "items" in schema:
            for i, item in enumerate(inst):
                errs += schema_errors(item, schema["items"], f"{path}[{i}]", root)
    if isinstance(inst, dict):
        for req in schema.get("required", []):
            if req not in inst:
                errs.append(f"{path}: missing required key {req!r}")
        props = schema.get("properties", {})
        for k, v in inst.items():
            if "propertyNames" in schema:
                errs += [e.replace("value", "key") for e in schema_errors(k, schema["propertyNames"], f"{path}.{k}", root)]
            if k in props:
                errs += schema_errors(v, props[k], f"{path}.{k}", root)
            else:
                ap = schema.get("additionalProperties", True)
                if ap is False:
                    errs.append(f"{path}: unknown key {k!r}")
                elif isinstance(ap, dict):
                    errs += schema_errors(v, ap, f"{path}.{k}", root)
    return errs


# --------------------------------------------------------------------------
# Key classification
# --------------------------------------------------------------------------
def is_protected(key):
    return key in PROTECTED_EXACT or key.startswith(PROTECTED_PREFIXES)


def is_secret_key(key):
    return bool(SECRET_SEGMENT.search(key.split(".")[-1]))


def secret_var_name(key):
    return "AS_SECRET_" + re.sub(r"[^A-Z0-9]", "_", key.upper())


def unprotected(cfg):
    """Config without protected keys. Protected keys such as subscription.saved_state change on
    their own (Q6), so they are never compared, written back or restored."""
    return {k: v for k, v in cfg.items() if not is_protected(k)}


def with_live_protected(cfg, live_cfg):
    """cfg's ordinary keys plus the server's current protected keys."""
    out = unprotected(cfg)
    out.update({k: v for k, v in live_cfg.items() if is_protected(k)})
    return out


def comparable(snap):
    """A snapshot without protected keys, for "has the server changed?" checks."""
    return {**snap, "config": unprotected(snap["config"])}


def mask(key, value, secret_keys=()):
    if value is None:
        return None
    if is_protected(key) or is_secret_key(key) or key in secret_keys:
        return "<secret>" if value else "''"
    return json.dumps(value)


# --------------------------------------------------------------------------
# sacli
# --------------------------------------------------------------------------
class Sacli:
    """Runs sacli. Options always go before the command (FINDINGS.md: option order)."""

    def __init__(self, path=None):
        self.path = path or next((p for p in SACLI_CANDIDATES if shutil.which(p)), None)
        if not self.path:
            raise Fail("sacli not found; is this an Access Server host? (use --sacli PATH)")

    def run(self, command, check=True, **opts):
        args = [self.path]
        for k, v in opts.items():
            args.append(f"--{k}={v}")
        args.append(command)
        p = subprocess.run(args, capture_output=True, text=True)
        out = p.stdout
        # Several commands report argument errors with exit code 0 (Q9, Q11).
        soft_error = re.search(r"^ERROR:|needs? to be specified", out + p.stderr, re.M)
        if check and (p.returncode != 0 or soft_error):
            shown = {k: ("<hidden>" if k in ("new_pass", "value") else v) for k, v in opts.items()}
            raise Fail(f"sacli {command} {shown} failed (rc={p.returncode}): {(out + p.stderr).strip()[:500]}")
        return p.returncode, out, p.stderr

    def json(self, command, **opts):
        _, out, _ = self.run(command, **opts)
        return first_json(out)

    def version(self):
        _, out, _ = self.run("Version")
        return out.strip().split()[0]

    def status(self):
        _, out, _ = self.run("Status", check=False)
        try:
            return first_json(out)
        except ValueError:
            return None


def first_json(text):
    """Parse the first JSON value in text (sacli start prints text around its JSON, Q2)."""
    stripped = text.strip()
    if stripped in ("None", ""):
        return None
    try:
        return json.loads(stripped)          # bare values such as a new ruleset id: "1"
    except ValueError:
        pass
    m = re.search(r"[\[{]", text)
    if not m:
        raise ValueError(f"no JSON in output: {text[:200]!r}")
    value, _ = json.JSONDecoder().raw_decode(text[m.start():])
    return value


# --------------------------------------------------------------------------
# Reading the server
# --------------------------------------------------------------------------
def owner_state(props):
    """User properties as file entries: no pvt_*, no type, access_to.N -> list."""
    state, access = {}, {}
    for k, v in props.items():
        if k.startswith("pvt_") or k == "type":
            continue
        m = re.fullmatch(r"access_to\.(\d+)", k)
        if m:
            access[int(m.group(1))] = v
        else:
            state[k] = v
    if access:
        state["access_to"] = [access[i] for i in sorted(access)]
    return state


def owner_props(state):
    """Inverse of owner_state, without the rulesets entry."""
    props = {k: v for k, v in state.items() if k not in ("access_to", "rulesets")}
    for i, v in enumerate(state.get("access_to", [])):
        props[f"access_to.{i}"] = v
    return props


def read_rulesets(sacli):
    """Return (rulesets by id, links by owner). Only rulesets attached to an owner are visible (Q9)."""
    rows = sacli.json("AccessControlRulesetsList") or []
    rulesets, links = {}, {}
    for r in rows:
        rulesets.setdefault(r["id"], {"name": r["name"], "comment": r.get("comment") or ""})
        links.setdefault(r["owner"], []).append([r["position"], r["id"]])
    for rid, rs in rulesets.items():
        rules = sacli.json("AccessControlRulesList", ruleset_id=rid) or []
        rules.sort(key=lambda x: x["position"])
        rs["rules"] = [{f: (x.get(f) or "") for f in RULE_FIELDS} for x in rules]
    for owner in links:
        links[owner].sort()
    return rulesets, links


def snapshot(sacli):
    """Everything apply may change, as the server reports it."""
    rulesets, links = read_rulesets(sacli)
    return {
        "access_server_version": sacli.version(),
        "config": sacli.json("ConfigQuery"),
        "userprops": sacli.json("UserPropGet"),
        "rulesets": {str(k): v for k, v in rulesets.items()},
        "links": links,
        "policies": sacli.json("ShowAllPolicies") or [],
    }


def rulesets_by_name(snap):
    out, dup = {}, set()
    for rs in snap["rulesets"].values():
        if rs["name"] in out:
            dup.add(rs["name"])
        out[rs["name"]] = {"comment": rs["comment"], "rules": rs["rules"]}
    return out, dup


def owner_ruleset_names(snap, owner):
    names = {k: v["name"] for k, v in snap["rulesets"].items()}
    return [names[str(rid)] for _, rid in snap["links"].get(owner, [])]


def file_view(snap):
    """The server's state in file terms (owners, rulesets, policies)."""
    rs, _ = rulesets_by_name(snap)
    groups, users = {}, {}
    for name, props in snap["userprops"].items():
        t = props.get("type")
        st = owner_state(props)
        rs_names = owner_ruleset_names(snap, name)
        if rs_names:
            st["rulesets"] = rs_names
        if t == "group" or name == DEFAULT_OWNER:
            groups[name] = st
        elif t in OWNER_TYPES_USER:
            users[name] = st
    return {"groups": groups, "users": users, "rulesets": rs, "policies": snap["policies"]}


# --------------------------------------------------------------------------
# Variables and secrets
# --------------------------------------------------------------------------
def read_values(path):
    values = {}
    if not path:
        return values
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                raise Fail(f"{path}:{n}: expected NAME=VALUE")
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            values[k.strip()] = v
    return values


def references(obj):
    found = set()
    if isinstance(obj, str):
        found |= {m.group(2) for m in VAR_RE.finditer(obj) if not m.group(1)}
    elif isinstance(obj, list):
        for x in obj:
            found |= references(x)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found |= references(v)
    return found


def substitute(obj, values):
    if isinstance(obj, str):
        def rep(m):
            if m.group(1):
                return "${" + m.group(2) + "}"
            return values[m.group(2)]
        return VAR_RE.sub(rep, obj)
    if isinstance(obj, list):
        return [substitute(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, values) for k, v in obj.items()}
    return obj


# --------------------------------------------------------------------------
# File checks shared by validate and apply
# --------------------------------------------------------------------------
def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise Fail(f"cannot read {path}: {e}")


def check_file(doc, values=None, need_values=False):
    """Return (errors, warnings)."""
    errors = schema_errors(doc)
    warnings = []
    if errors:
        return errors, warnings
    cfg = doc["config"]
    declared_vars = set(doc.get("variables", []))
    declared_secrets = set(doc.get("secrets", []))
    for both in declared_vars & declared_secrets:
        errors.append(f"{both} is listed in both variables and secrets")
    used = references({k: v for k, v in doc.items() if k not in ("variables", "secrets")})
    for name in sorted(used - declared_vars - declared_secrets):
        errors.append(f"${{{name}}} is used but not listed in variables or secrets")
    for name in sorted((declared_vars | declared_secrets) - used):
        warnings.append(f"{name} is declared but never used")
    if values is not None or need_values:
        for name in sorted(declared_vars):
            if name not in (values or {}):
                errors.append(f"variable {name} has no value in the values file")
    for k in sorted(set(cfg["set"]) & set(cfg["unset"])):
        errors.append(f"config key {k} is in both set and unset")
    for k in list(cfg["set"]) + list(cfg["unset"]):
        if is_protected(k):
            warnings.append(f"config key {k} is protected and will be skipped")
    for k in cfg["unset"]:
        if k in REINSERTED and not is_protected(k):
            errors.append(f"config key {k} cannot be unset: ConfigReplace re-inserts it")
    for k, v in cfg["set"].items():
        if is_secret_key(k) and not is_protected(k) and not references(v):
            warnings.append(f"config key {k} looks secret but holds a literal value; use ${{{secret_var_name(k)}}}")
    names = set(doc.get("rulesets", {}))
    owners = {**doc.get("groups", {}), **doc.get("users", {})}
    attached = set()
    for owner, st in owners.items():
        for rs in st.get("rulesets", []):
            attached.add(rs)
            if "rulesets" in doc and rs not in names:
                errors.append(f"{owner} uses ruleset {rs!r}, which is not defined in rulesets")
    if "rulesets" not in doc and attached:
        errors.append("owners list rulesets but the file has no rulesets section")
    for rs in sorted(names - attached):
        errors.append(f"ruleset {rs!r} is not assigned to any group or user; Access Server cannot list unassigned rulesets")
    if DEFAULT_OWNER in doc.get("users", {}):
        errors.append("__DEFAULT__ belongs in groups, not users")
    pol = [p["name"] for p in doc.get("policies", [])]
    if len(pol) != len(set(pol)):
        errors.append("policy names must be unique")
    for owner, st in owners.items():
        for p in [x.strip() for x in st.get("policy", "").split(",") if x.strip()]:
            if "policies" in doc and p not in pol:
                warnings.append(f"{owner} refers to policy {p!r}, which is not in policies")
    return errors, warnings


def check_version(doc_version, live_version, force):
    if doc_version != live_version:
        msg = f"file is for Access Server {doc_version}, this server runs {live_version}"
        if not force:
            raise Fail(msg + "; refusing (use --force-version to override)")
        log(f"WARNING: {msg}; continuing because of --force-version")


def require_root():
    if os.geteuid() != 0:
        raise Fail("must run as root (sacli needs it)")


def wait_for_api(sacli, timeout):
    deadline = time.time() + timeout
    while True:
        st = sacli.status()
        if st and st.get("service_status", {}).get("api") == "on":
            return
        if time.time() > deadline:
            raise Fail(f"Access Server API not on after {timeout}s")
        time.sleep(3)


def sacli_validate(sacli):
    _, out, _ = sacli.run("Validate", check=False)
    try:
        return first_json(out) or {}
    except ValueError:
        return {"_unparsed": out.strip()}


# --------------------------------------------------------------------------
# baseline / export
# --------------------------------------------------------------------------
def scrub_config(cfg):
    """Baseline copies keep no secrets: protected and secret values become hashes."""
    out = {}
    for k, v in cfg.items():
        if is_protected(k) or is_secret_key(k):
            out[k] = "sha256:" + hashlib.sha256(v.encode()).hexdigest()
        else:
            out[k] = v
    return out


def cmd_baseline(args):
    require_root()
    sacli = Sacli(args.sacli)
    wait_for_api(sacli, args.wait)
    snap = snapshot(sacli)
    snap["config"] = scrub_config(snap["config"])
    for props in snap["userprops"].values():
        for k in [k for k in props if k.startswith("pvt_")]:
            del props[k]
    doc = {"kind": "as-config-baseline", "format": FORMAT, "taken_at": utc_now(), **snap}
    write_json(args.output, doc, private=True)
    log(f"baseline of Access Server {snap['access_server_version']} written to {args.output} "
        f"({len(snap['config'])} config keys, {len(snap['userprops'])} user records)")


def cmd_export(args):
    require_root()
    sacli = Sacli(args.sacli)
    wait_for_api(sacli, args.wait)
    base = load_json(args.baseline)
    if base.get("kind") != "as-config-baseline":
        raise Fail(f"{args.baseline} is not a baseline file")
    live = snapshot(sacli)
    if base["access_server_version"] != live["access_server_version"]:
        raise Fail(f"baseline is from Access Server {base['access_server_version']}, "
                   f"this server runs {live['access_server_version']}; take a new baseline")
    warnings = []
    bcfg, lcfg = base["config"], scrub_config(live["config"])
    cset, unset, secret_names = {}, [], []
    for k in sorted(set(bcfg) | set(lcfg)):
        if is_protected(k) or bcfg.get(k) == lcfg.get(k):
            continue
        if k not in lcfg:
            unset.append(k)
        elif is_secret_key(k):
            name = secret_var_name(k)
            cset[k] = "${" + name + "}"
            secret_names.append(name)
        else:
            cset[k] = escape_refs(live["config"][k])
            if IP_LIKE.search(cset[k]):
                warnings.append(f"config {k} = {cset[k]!r} looks environment-specific; consider a ${{VARIABLE}}")
    for k in unset:
        if k in REINSERTED:
            warnings.append(f"config {k} was removed but ConfigReplace re-inserts it; leaving it out of unset")
    unset = [k for k in unset if k not in REINSERTED]

    bview, lview = file_view(base), file_view(live)
    _, dup = rulesets_by_name(live)
    if dup:
        raise Fail(f"duplicate ruleset names on this server: {sorted(dup)}; rename them first")

    def esc(x):
        return substitute_literal(x)

    def hide_owner_secrets(owner, st):
        out = {}
        for k, v in st.items():
            if isinstance(v, str) and is_secret_key(k):
                var = "AS_SECRET_" + re.sub(r"[^A-Z0-9]", "_", f"{owner}_{k}".upper())
                out[k] = "${" + var + "}"
                secret_names.append(var)
            else:
                out[k] = v
        return out

    groups = {}
    for name, st in sorted(lview["groups"].items()):
        if name == DEFAULT_OWNER and st == bview["groups"].get(DEFAULT_OWNER):
            continue
        groups[name] = hide_owner_secrets(name, esc(st))
    users = {}
    for name, st in sorted(lview["users"].items()):
        if st != bview["users"].get(name):
            users[name] = hide_owner_secrets(name, esc(st))
    for name in sorted(set(bview["users"]) - set(lview["users"])):
        warnings.append(f"user {name} was deleted since the baseline; apply only deletes users with --prune-users")

    doc = {
        "format": FORMAT,
        "access_server_version": live["access_server_version"],
        "generated_by": f"as_config.py {TOOL_VERSION} export, {utc_now()}",
        "config": {"set": cset, "unset": unset},
        "groups": groups,
    }
    if users:
        doc["users"] = users
    if lview["rulesets"] or bview["rulesets"]:
        doc["rulesets"] = esc(lview["rulesets"])
    if lview["policies"] != bview["policies"]:
        doc["policies"] = esc(lview["policies"])
    doc["variables"] = []
    doc["secrets"] = secret_names
    for name, st in {**groups, **users}.items():
        for rule in st.get("access_to", []):
            if IP_LIKE.search(rule):
                warnings.append(f"{name} access_to {rule!r} looks environment-specific; consider a ${{VARIABLE}}")
    write_json(args.output, doc)
    for w in warnings:
        log(f"note: {w}")
    log(f"exported {len(cset)} set, {len(unset)} unset, {len(groups)} groups, {len(users)} users, "
        f"{len(doc.get('rulesets', {}))} rulesets, policies {'included' if 'policies' in doc else 'unchanged'} "
        f"-> {args.output}")
    if secret_names:
        log(f"secrets to provide as environment variables at apply time: {', '.join(secret_names)}")


def escape_refs(text):
    """Escape exactly the ${NAME} sequences that substitute() would replace, so they stay literal.
    Other text with ${ (for example "${1}" or a lone "${") is left alone, because substitute()
    leaves it alone too."""
    return re.sub(r"\$(?=\{[A-Za-z_][A-Za-z0-9_]*\})", "$$", text)


def substitute_literal(obj):
    """Escape ${NAME} in exported values so they stay literal."""
    if isinstance(obj, str):
        return escape_refs(obj)
    if isinstance(obj, list):
        return [substitute_literal(x) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute_literal(v) for k, v in obj.items()}
    return obj


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------
def cmd_validate(args):
    doc = load_json(args.file)
    values = read_values(args.values) if args.values else None
    errors, warnings = check_file(doc, values)
    sacli = None
    if not errors and not args.offline:
        try:
            sacli = Sacli(args.sacli)
        except Fail:
            sacli = None
    if sacli and os.geteuid() == 0:
        known = set(sacli.json("ConfigDefaults") or {}) | set(sacli.json("ConfigQuery") or {})
        known_shapes = {re.sub(r"\.\d+(?=\.|$)", ".N", k) for k in known}
        for k in doc["config"]["set"]:
            shape = re.sub(r"\.\d+(?=\.|$)", ".N", k)
            if k not in known and shape not in known_shapes and not is_protected(k):
                warnings.append(f"config key {k} is not known to this server (typo?); Access Server stores unknown keys silently")
        live = sacli.version()
        if live != doc["access_server_version"]:
            warnings.append(f"file is for {doc['access_server_version']}, this server runs {live}")
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if errors:
        raise Fail(f"{args.file}: {len(errors)} error(s)")
    managed = [f"--prune-{n}" for n in ("groups", "users", "rulesets", "policies") if n in doc]
    if managed:
        print("note: apply keeps groups, users, rulesets and policies that exist on the server but are not in this file; "
              f"to delete them, add {' '.join(managed)} (check with --dry-run first)")
    print(f"{args.file}: valid" + (f" ({len(warnings)} warning(s))" if warnings else ""))


# --------------------------------------------------------------------------
# apply: plan
# --------------------------------------------------------------------------
class Plan:
    def __init__(self):
        self.lines = []             # changes, deletions start with DELETE
        self.kept = []              # target items the file does not mention, kept for lack of a prune flag
        self.config = None          # merged config to replace with, or None
        self.policies = None        # merged policy list to write, or None
        self.expected_policies = None
        self.owner_ops = []         # (owner, kind, create_type, puts{}, dels[])
        self.owner_deletes = []     # owners to delete (pruned groups / users)
        self.expected_groups = None
        self.rs_create = []         # (name, spec)
        self.rs_update = []         # (name, id, spec, comment_changed, rules_changed)
        self.rs_delete = []         # (name, id)
        self.expected_rulesets = None
        self.links = []             # (owner, [names])
        self.expected_links = {}    # owner -> [names] after apply
        self.new_local_users = []
        self.created_rulesets = []  # ids created by execute(); unassigned ones are invisible to restore (Q9)

    @property
    def empty(self):
        return not self.lines

    def add(self, line):
        self.lines.append(line)

    def keep(self, flag, what):
        self.kept.append(f"KEPT (use --prune-{flag}) {what}")


def norm_spec(spec):
    return {"comment": spec.get("comment", ""), "rules": [{f: r.get(f, "") for f in RULE_FIELDS} for r in spec["rules"]]}


def build_plan(doc, live, args, secret_names, sensitive=frozenset()):
    """sensitive: {(owner, property)} whose values must never be shown."""
    plan = Plan()
    lcfg = live["config"]
    merged = dict(lcfg)
    for k, v in doc["config"]["set"].items():
        if is_protected(k):
            log(f"skip protected key {k}")
            continue
        if lcfg.get(k) != v:
            if k in lcfg:
                plan.add(f"config ~ {k}: {mask(k, lcfg[k], secret_names)} -> {mask(k, v, secret_names)}")
            else:
                plan.add(f"config + {k} = {mask(k, v, secret_names)}")
        merged[k] = v
    for k in doc["config"]["unset"]:
        if is_protected(k):
            log(f"skip protected key {k}")
            continue
        if k in merged:
            plan.add(f"DELETE config {k} (was {mask(k, merged[k], secret_names)})")
            del merged[k]
    if merged != lcfg:
        plan.config = merged

    # Policies: merge by name into the live list (SetAllPoliciesFromFile replaces the whole set).
    if "policies" in doc:
        wanted = {p["name"]: p for p in doc["policies"]}
        result = []
        for p in live["policies"]:
            name = p.get("name")
            if name in wanted:
                if wanted[name] != p:
                    plan.add(f"policy ~ {name}")
                result.append(wanted[name])
            elif args.prune_policies:
                plan.add(f"DELETE policy {name}")
            else:
                plan.keep("policies", f"policy {name}")
                result.append(p)
        live_names = {p.get("name") for p in live["policies"]}
        for p in doc["policies"]:
            if p["name"] not in live_names:
                plan.add(f"policy + {p['name']}")
                result.append(p)
        plan.expected_policies = result
        if result != live["policies"]:
            plan.policies = result

    view = file_view(live)
    manage_rs = "rulesets" in doc
    kept_rs = set()
    if manage_rs:
        lrs, dup = rulesets_by_name(live)
        ids = {rs["name"]: int(rid) for rid, rs in live["rulesets"].items()}
        expected = {}
        for name, spec in doc["rulesets"].items():
            spec = norm_spec(spec)
            expected[name] = spec
            if name in dup:
                raise Fail(f"ruleset name {name!r} is used more than once on this server; rename one first")
            if name not in lrs:
                plan.add(f"ruleset + {name} ({len(spec['rules'])} rules)")
                plan.rs_create.append((name, spec))
            elif lrs[name] != spec:
                cc = lrs[name]["comment"] != spec["comment"]
                rc = lrs[name]["rules"] != spec["rules"]
                plan.add(f"ruleset ~ {name}: " + ", ".join(x for x, y in (("comment", cc), ("rules", rc)) if y))
                plan.rs_update.append((name, ids[name], spec, cc, rc))
        for name in sorted(set(lrs) - set(doc["rulesets"])):
            if not args.prune_rulesets:
                plan.keep("rulesets", f"ruleset {name}")
                kept_rs.add(name)
                expected[name] = lrs[name]
                continue
            if name in dup:
                raise Fail(f"ruleset name {name!r} is used more than once on this server; rename one first")
            plan.add(f"DELETE ruleset {name}")
            plan.rs_delete.append((name, ids[name]))
        plan.expected_rulesets = expected

    def show(owner, k, v):
        return "<secret>" if (owner, k) in sensitive or is_secret_key(k) else json.dumps(v)

    def plan_owner(name, desired, current, kind, create_type):
        dprops = owner_props(desired)
        cprops = owner_props(current) if current is not None else {}
        puts = {k: v for k, v in dprops.items() if cprops.get(k) != v}
        dels = sorted(k for k in cprops if k not in dprops)
        if current is None:
            plan.add(f"{kind} + {name}")
        for k in sorted(puts):
            plan.add(f"{kind} {name}: {k} = {show(name, k, puts[k])}" + (f" (was {show(name, k, cprops[k])})" if k in cprops else ""))
        for k in dels:
            plan.add(f"{kind} {name}: remove {k} (was {show(name, k, cprops[k])})")
        if current is None or puts or dels:
            plan.owner_ops.append((name, kind, create_type if current is None else None, puts, dels))
        if manage_rs:
            have = current.get("rulesets", []) if current is not None else []
            want = list(desired.get("rulesets", []))
            # Links to rulesets kept on the target stay, after the file's own, so they never become unassigned.
            want += [n for n in have if n in kept_rs and n not in want]
            plan.expected_links[name] = want
            if want != have:
                plan.add(f"{kind} {name}: rulesets {have} -> {want}")
                plan.links.append((name, want))

    if "groups" in doc:
        for name, desired in doc["groups"].items():
            current = view["groups"].get(name)
            if name == DEFAULT_OWNER and current is None:
                current = {}
            plan_owner(name, desired, current, "group", "group")
        expected_groups = set(view["groups"]) | set(doc["groups"])
        for name in sorted(set(view["groups"]) - set(doc["groups"]) - {DEFAULT_OWNER}):
            if args.prune_groups:
                plan.add(f"DELETE group {name}")
                plan.owner_deletes.append(name)
                expected_groups.discard(name)
            else:
                plan.keep("groups", f"group {name}")
        plan.expected_groups = expected_groups

    if "users" in doc:
        auth_default = live["config"].get("auth.module.type", "local")
        for name, desired in doc["users"].items():
            current = view["users"].get(name)
            if name in view["groups"]:
                raise Fail(f"{name} is a group on this server, the file lists it as a user")
            plan_owner(name, desired, current, "user", "user_connect")
            if current is None and desired.get("user_auth_type", auth_default) == "local":
                plan.new_local_users.append(name)
                plan.add(f"user {name}: new local user, temporary password will be generated")
        for name in sorted(set(view["users"]) - set(doc["users"])):
            if view["users"][name].get("prop_superuser") == "true":
                plan.kept.append(f"KEPT (superuser, never pruned) user {name}")
            elif args.prune_users:
                plan.add(f"DELETE user {name}")
                plan.owner_deletes.append(name)
            else:
                plan.keep("users", f"user {name}")
    return plan


# --------------------------------------------------------------------------
# apply: execute
# --------------------------------------------------------------------------
def write_private(path, data):
    """Write a root-only file inside a checked private directory, never through a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_json(path, doc, private=False):
    """Write path atomically. The temporary file is created exclusively with a random name in the
    same directory, and os.replace swaps it in without following a symlink at path, so a planted
    link cannot redirect the write to another file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600 if private else 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def check_private_dir(path, what):
    """Refuse a directory that is a symlink, not owned by root, or writable by others,
    and one whose parent lets others rename it away."""
    st = os.lstat(path)
    if not os.path.isdir(path) or os.path.islink(path):
        raise Fail(f"{what} {path} must be a real directory, not a symlink")
    if st.st_uid != 0 or st.st_mode & 0o077:
        raise Fail(f"{what} {path} must be owned by root with mode 700 (found owner {st.st_uid}, mode {oct(st.st_mode & 0o777)})")
    parent = os.lstat(os.path.dirname(os.path.abspath(path)))
    if parent.st_mode & 0o002 and not parent.st_mode & 0o1000:
        raise Fail(f"{what} {path} is inside a directory anyone can write to")


def prepare_state_dir(state_dir):
    if not os.path.lexists(state_dir):
        os.makedirs(state_dir, mode=0o700)
    check_private_dir(state_dir, "state directory")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_backup(state_dir, snap, sacli):
    prepare_state_dir(state_dir)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    d = os.path.join(state_dir, f"backup-{stamp}")
    os.mkdir(d, 0o700)
    write_private(os.path.join(d, "snapshot.json"), snap)
    write_private(os.path.join(d, "validate-before.json"), sacli_validate(sacli))
    return d


def put_props(sacli, owner, props, workdir, sensitive=frozenset()):
    """UserPropPut each property. Secret values (secret-looking property names, values taken from
    `secrets`, or sensitive=True for everything) and long or multi-line values go through a file in
    workdir (the root-only backup directory, deleted straight after), so they never appear on a
    command line or in /tmp."""
    for k, v in props.items():
        secret = sensitive is True or (owner, k) in sensitive or is_secret_key(k)
        if secret or "\n" in v or len(v) > 1000:
            fd, path = tempfile.mkstemp(dir=workdir, prefix="prop-")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(v)
                sacli.run("UserPropPut", user=owner, key=k, value_file=path)
            finally:
                os.unlink(path)
        else:
            sacli.run("UserPropPut", user=owner, key=k, value=v)


def del_props(sacli, owner, keys):
    for k in keys:
        sacli.run("UserPropDel", user=owner, key=k)


def create_ruleset(sacli, name, spec, created=None):
    _, out, _ = sacli.run("AccessControlRulesetsAdd", name=name, comment=spec["comment"])
    rid = first_json(out)
    if not isinstance(rid, int):
        m = re.search(r"\d+", out)
        if not m:
            raise Fail(f"could not read the id of new ruleset {name}: {out!r}")
        rid = int(m.group())
    if created is not None:
        created.append(rid)
    add_rules(sacli, rid, spec["rules"])
    return rid


def add_rules(sacli, rid, rules):
    for pos, r in enumerate(rules, 1):
        sacli.run("AccessControlRulesAdd", ruleset_id=rid, rule_type=r["type"], match_type=r["match_type"],
                  match_data=r["match_data"], action=r["action"], position=pos, comment=r.get("comment", ""))


def current_rule_ids(sacli, rid):
    return [r["id"] for r in (sacli.json("AccessControlRulesList", ruleset_id=rid) or [])]


def set_links(sacli, owner, names, ids_by_name, current_links):
    for _, rid in current_links.get(owner, []):
        sacli.run("AccessControlUserRulesetsDelete", user=owner, ruleset_id=rid)
    for pos, name in enumerate(names, 1):
        sacli.run("AccessControlUserRulesetsAdd", user=owner, ruleset_id=ids_by_name[name], position=pos)


def run_start(sacli):
    rc, out, err = sacli.run("start", check=False)
    try:
        info = first_json(out) or {}
    except ValueError:
        info = {}
    errors = {k: v for k, v in (info.get("errors") or {}).items()
              if any(isinstance(m, dict) and m.get("severity") == "error" for m in v)}
    if rc != 0 or errors:
        raise Fail(f"sacli start failed (rc={rc}): {json.dumps(errors)[:800] or out[:400]}")


def execute(plan, doc, sacli, live, backup_dir, secret_names, sensitive=frozenset()):
    if plan.config is not None:
        # Take protected keys from the server right now, not from planning time (they change on their own).
        plan.config = with_live_protected(plan.config, sacli.json("ConfigQuery"))
        path = os.path.join(backup_dir, "applied-config.json")
        write_private(path, plan.config)
        sacli.run("ConfigReplace", value_file=path)
        before = load_json(os.path.join(backup_dir, "validate-before.json"))
        after = sacli_validate(sacli)
        new = {k: v for k, v in after.items() if before.get(k) != v}
        if new:
            raise Fail(f"sacli Validate rejected the new configuration: {json.dumps(new)[:800]}")
        log("config replaced and validated")

    if plan.policies is not None:
        path = os.path.join(backup_dir, "applied-policies.json")
        write_private(path, plan.policies)
        sacli.run("SetAllPoliciesFromFile", value_file=path)
        log("policies written")

    # Owners first (rulesets attach to them), deletions last.
    for name, kind, create_type, puts, dels in plan.owner_ops:
        if create_type:
            sacli.run("UserPropPut", user=name, key="type", value=create_type)
        put_props(sacli, name, puts, backup_dir, sensitive)
        del_props(sacli, name, dels)
    if plan.owner_ops:
        log(f"{len(plan.owner_ops)} groups/users written")

    passwords = {}
    for name in plan.new_local_users:
        pw = pysecrets.token_urlsafe(18)
        _, out, _ = sacli.run("SetLocalPassword", user=name, new_pass=pw)
        res = first_json(out) or {}
        if res.get("status") is not True:
            raise Fail(f"could not set a password for {name}: {res.get('reason')}")
        passwords[name] = pw
    if passwords:
        path = os.path.join(backup_dir, "temporary-passwords.json")
        write_private(path, passwords)
        log(f"{len(passwords)} temporary password(s) written to {path} (root only)")

    rs_now, links_now = read_rulesets(sacli)
    ids = {v["name"]: k for k, v in rs_now.items()}
    for name, spec in plan.rs_create:
        ids[name] = create_ruleset(sacli, name, spec, plan.created_rulesets)
    if os.environ.get("AS_CONFIG_TEST_FAIL_AFTER_RULESET_CREATE") == "1":
        raise Fail("forced failure after creating rulesets (AS_CONFIG_TEST_FAIL_AFTER_RULESET_CREATE=1)")
    for name, rid, spec, cc, rc in plan.rs_update:
        if cc:
            sacli.run("AccessControlRulesetsUpdate", ruleset_id=rid, name=name, comment=spec["comment"])
        if rc:
            for rule_id in current_rule_ids(sacli, rid):
                sacli.run("AccessControlRulesDelete", rule_id=rule_id)
            add_rules(sacli, rid, spec["rules"])
    for owner, names in plan.links:
        set_links(sacli, owner, names, ids, links_now)
    for name, rid in plan.rs_delete:
        sacli.run("AccessControlRulesetsDelete", ruleset_id=rid)
    if plan.rs_create or plan.rs_update or plan.rs_delete or plan.links:
        log("rulesets synced")

    for name in plan.owner_deletes:
        sacli.run("UserPropDelAll", user=name)
    if plan.owner_deletes:
        log(f"deleted {', '.join(plan.owner_deletes)}")

    run_start(sacli)
    log("sacli start: ok")


def verify(doc, plan, live_before, sacli, args, sensitive=frozenset(), secret_keys=frozenset()):
    """Compare the server with what the plan intended. Returns a list of mismatches (secret values masked)."""
    after = snapshot(sacli)
    problems = []
    want_cfg = plan.config if plan.config is not None else live_before["config"]
    for k in sorted(set(want_cfg) | set(after["config"])):
        if is_protected(k):
            continue
        if want_cfg.get(k) != after["config"].get(k):
            problems.append(f"config {k}: expected {mask(k, want_cfg.get(k), secret_keys)}, "
                            f"found {mask(k, after['config'].get(k), secret_keys)}")
    if plan.expected_policies is not None and after["policies"] != plan.expected_policies:
        problems.append(f"policies: expected {[p.get('name') for p in plan.expected_policies]}, "
                        f"found {[p.get('name') for p in after['policies']]}")
    view = file_view(after)

    def cmp_owner(kind, name, desired, actual):
        if actual is None:
            problems.append(f"{kind} {name} is missing")
            return
        a, d = owner_props(actual), owner_props(desired)
        for k in sorted(set(a) | set(d)):
            if a.get(k) != d.get(k):
                hide = (name, k) in sensitive or is_secret_key(k)
                shown = (lambda v: "<secret>" if hide and v is not None else json.dumps(v))
                problems.append(f"{kind} {name}: {k} expected {shown(d.get(k))}, found {shown(a.get(k))}")
        if name in plan.expected_links and actual.get("rulesets", []) != plan.expected_links[name]:
            problems.append(f"{kind} {name}: rulesets expected {plan.expected_links[name]}, found {actual.get('rulesets', [])}")

    if "groups" in doc:
        for name, desired in doc["groups"].items():
            cmp_owner("group", name, desired, view["groups"].get(name))
        found = set(view["groups"])
        if found != plan.expected_groups:
            problems.append(f"groups: expected {sorted(plan.expected_groups)}, found {sorted(found)}")
    for name, desired in doc.get("users", {}).items():
        cmp_owner("user", name, desired, view["users"].get(name))
    for name in plan.owner_deletes:
        if name in view["users"] or name in view["groups"]:
            problems.append(f"{name} should have been deleted")
    if plan.expected_rulesets is not None:
        rs, _ = rulesets_by_name(after)
        if rs != plan.expected_rulesets:
            problems.append(f"rulesets differ: expected {sorted(plan.expected_rulesets)}, found {sorted(rs)}")
    if os.environ.get("AS_CONFIG_TEST_FAIL_VERIFY") == "1":
        problems.append("forced verify failure (AS_CONFIG_TEST_FAIL_VERIFY=1)")
    return problems


def sensitive_props(doc, secret_names):
    """(owner, property) pairs whose values are secret: the name looks secret, or the value uses `secrets`."""
    out = set()
    for section in ("groups", "users"):
        for owner, st in doc.get(section, {}).items():
            for k, v in owner_props(st).items():
                if is_secret_key(k) or references(v) & secret_names:
                    out.add((owner, k))
    return out


def cmd_apply(args):
    require_root()
    doc = load_json(args.file)
    values = read_values(args.values)
    errors, warnings = check_file(doc, values, need_values=bool(doc.get("variables")))
    for w in warnings:
        log(f"warning: {w}")
    if errors:
        for e in errors:
            log(f"error: {e}")
        raise Fail(f"{args.file} is not valid; nothing changed")
    secret_names = set(doc.get("secrets", []))
    missing = sorted(n for n in secret_names if n not in os.environ)
    if missing:
        raise Fail(f"secrets missing from the environment: {', '.join(missing)}")
    values.update({n: os.environ[n] for n in secret_names})
    for n in secret_names:
        add_secret(os.environ[n])
    resolved = substitute({k: v for k, v in doc.items() if k not in ("variables", "secrets")}, values)
    secret_keys = {k for k, v in doc["config"]["set"].items() if references(v) & secret_names}
    sensitive = sensitive_props(doc, secret_names)

    sacli = Sacli(args.sacli)
    check_version(doc["access_server_version"], sacli.version(), args.force_version)
    wait_for_api(sacli, args.wait)

    live = snapshot(sacli)
    remember_secrets(live)
    plan = build_plan(resolved, live, args, secret_keys, sensitive)
    if plan.kept:
        print(f"{len(plan.kept)} item(s) on this server are not in the file and will be kept:")
        for line in plan.kept:
            print("  warning: " + line)
    if plan.empty:
        print("no changes")
        return
    deletions = sum(1 for line in plan.lines if line.startswith("DELETE"))
    print(f"{len(plan.lines)} change(s), {deletions} deletion(s):")
    for line in plan.lines:
        print("  " + line)
    sys.stdout.flush()
    if args.dry_run:
        print("dry run: nothing written")
        return

    lock = take_lock(args.state_dir)  # noqa: F841 - held until the process exits
    live2 = snapshot(sacli)
    if comparable(live2) != comparable(live):
        raise Fail("the server changed while planning; run apply again")
    backup_dir = make_backup(args.state_dir, live, sacli)
    log(f"backup: {backup_dir}")
    try:
        execute(plan, resolved, sacli, live, backup_dir, secret_keys, sensitive)
        problems = verify(resolved, plan, live, sacli, args, sensitive, secret_keys)
        if problems:
            raise Fail("verification failed:\n  " + "\n  ".join(problems))
    except Exception as e:  # noqa: BLE001 - any failure after the backup must roll back
        log(f"ERROR: {e if isinstance(e, Fail) else repr(e)}")
        log(f"rolling back from {backup_dir}")
        try:
            for rid in plan.created_rulesets:   # may be unassigned, so restore() could not see them
                sacli.run("AccessControlRulesetsDelete", check=False, ruleset_id=rid)
            restore(sacli, backup_dir)
        except Exception as e2:  # noqa: BLE001 - report anything that stops the restore
            raise Fail(f"ROLLBACK FAILED: {e2}; restore by hand with: as_config.py rollback {backup_dir}", code=4)
        raise Fail("apply failed; the server was restored from the backup", code=3)
    print(f"applied; backup kept in {backup_dir}")
    if plan.new_local_users:
        print(f"hand out the temporary passwords in {backup_dir}/temporary-passwords.json, then delete that file")
    prune_backups(args.state_dir, args.keep_backups, keep=backup_dir)


def prune_backups(state_dir, count, keep):
    """Delete the oldest backup directories so that at most `count` remain. Backups hold
    password hashes and secrets, so they should not pile up. `keep` is never deleted."""
    if count <= 0:
        return
    names = sorted(n for n in os.listdir(state_dir) if re.fullmatch(r"backup-\d{8}T\d+Z", n))
    for name in names[:-count]:
        path = os.path.join(state_dir, name)
        if os.path.abspath(path) == os.path.abspath(keep) or os.path.islink(path) or not os.path.isdir(path):
            continue
        shutil.rmtree(path)
        log(f"removed old backup {path} (--keep-backups {count})")


# --------------------------------------------------------------------------
# rollback
# --------------------------------------------------------------------------
def restore(sacli, backup_dir):
    snap = load_json(os.path.join(backup_dir, "snapshot.json"))
    live = snapshot(sacli)
    changed = False

    if unprotected(live["config"]) != unprotected(snap["config"]):
        path = os.path.join(backup_dir, "restore-config.json")
        write_private(path, with_live_protected(snap["config"], live["config"]))
        sacli.run("ConfigReplace", value_file=path)
        changed = True
    if live["policies"] != snap["policies"]:
        path = os.path.join(backup_dir, "restore-policies.json")
        write_private(path, snap["policies"])
        sacli.run("SetAllPoliciesFromFile", value_file=path)
        changed = True

    # Rulesets: compare by name, recreate everything when anything differs.
    def rs_canon(s):
        names = {k: v["name"] for k, v in s["rulesets"].items()}
        return (sorted((v["name"], v["comment"], json.dumps(v["rules"], sort_keys=True)) for v in s["rulesets"].values()),
                {o: [names[str(r)] for _, r in l] for o, l in s["links"].items()})
    rs_differ = rs_canon(live) != rs_canon(snap)
    if rs_differ:
        for rid in live["rulesets"]:
            sacli.run("AccessControlRulesetsDelete", ruleset_id=rid)

    bprops, lprops = snap["userprops"], live["userprops"]
    for name in sorted(set(lprops) - set(bprops)):
        sacli.run("UserPropDelAll", user=name)
        changed = True
    for name, props in bprops.items():
        cur = lprops.get(name, {})
        if cur == props:
            continue
        if "type" in props and cur.get("type") != props["type"]:
            sacli.run("UserPropPut", user=name, key="type", value=props["type"])
        put_props(sacli, name, {k: v for k, v in props.items() if k != "type" and cur.get(k) != v}, backup_dir, True)
        del_props(sacli, name, [k for k in cur if k not in props])
        changed = True

    if rs_differ:
        ids = {}
        for old_id, rs in snap["rulesets"].items():
            ids[old_id] = create_ruleset(sacli, rs["name"], rs)
        for owner, links in snap["links"].items():
            for pos, old in links:
                sacli.run("AccessControlUserRulesetsAdd", user=owner, ruleset_id=ids[str(old)], position=pos)
        changed = True

    if changed:
        run_start(sacli)
    after = snapshot(sacli)
    mism = []
    if unprotected(after["config"]) != unprotected(snap["config"]):
        mism.append("config")
    if after["userprops"] != snap["userprops"]:
        mism.append("users/groups")
    if after["policies"] != snap["policies"]:
        mism.append("policies")
    if rs_canon(after) != rs_canon(snap):
        mism.append("rulesets")
    if mism:
        raise Fail(f"after restore these still differ from the backup: {', '.join(mism)}")
    log("restore complete: server matches the backup")


def take_lock(state_dir):
    prepare_state_dir(state_dir)
    fd = os.open(os.path.join(state_dir, ".lock"), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    lock = os.fdopen(fd, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Fail("another as_config.py apply or rollback is running")
    return lock


def cmd_rollback(args):
    require_root()
    if not os.path.isfile(os.path.join(args.backup_dir, "snapshot.json")):
        raise Fail(f"{args.backup_dir} is not an as-config backup (no snapshot.json)")
    check_private_dir(args.backup_dir, "backup directory")
    check_private_dir(os.path.dirname(os.path.abspath(args.backup_dir)), "state directory")
    snap_path = os.path.join(args.backup_dir, "snapshot.json")
    if os.path.islink(snap_path) or os.lstat(snap_path).st_uid != 0:
        raise Fail(f"{snap_path} must be a root-owned file, not a symlink")
    sacli = Sacli(args.sacli)
    wait_for_api(sacli, args.wait)
    snap = load_json(snap_path)
    remember_secrets(snap)
    check_version(snap["access_server_version"], sacli.version(), args.force_version)
    lock = take_lock(os.path.dirname(os.path.abspath(args.backup_dir)))  # noqa: F841
    restore(sacli, args.backup_dir)
    print(f"rolled back to {args.backup_dir}")


def cmd_schema(args):
    print(json.dumps(SCHEMA, indent=2))


# --------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(prog="as_config.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=f"as_config.py {TOOL_VERSION} (format {FORMAT})")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--sacli", help="path to sacli (default: from PATH or /usr/local/openvpn_as/scripts/sacli)")
        sp.add_argument("--wait", type=int, default=300, help="seconds to wait for the API to come up (default 300)")

    sp = sub.add_parser("baseline", help="save the state of a fresh server")
    sp.add_argument("-o", "--output", required=True)
    common(sp)
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("export", help="write the differences from a baseline")
    sp.add_argument("--baseline", required=True)
    sp.add_argument("-o", "--output", required=True)
    common(sp)
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("validate", help="check a file without changing anything")
    sp.add_argument("file")
    sp.add_argument("--values", help="NAME=VALUE file; checks that every variable resolves")
    sp.add_argument("--offline", action="store_true", help="do not consult a local Access Server")
    common(sp)
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("apply", help="apply a file to this server")
    sp.add_argument("file")
    sp.add_argument("--values", help="NAME=VALUE file with the variables")
    sp.add_argument("--dry-run", action="store_true", help="print the changes and stop")
    sp.add_argument("--force-version", action="store_true", help="apply even if the Access Server version differs")
    sp.add_argument("--prune-groups", action="store_true", help="delete groups that are not in the file")
    sp.add_argument("--prune-rulesets", action="store_true", help="delete rulesets that are not in the file")
    sp.add_argument("--prune-policies", action="store_true", help="delete policies that are not in the file")
    sp.add_argument("--prune-users", action="store_true",
                    help="delete users that are not in the file (superusers are never deleted)")
    sp.add_argument("--state-dir", default=DEFAULT_STATE_DIR,
                    help=f"where backups go; must be root-only (default {DEFAULT_STATE_DIR})")
    sp.add_argument("--keep-backups", type=int, default=10,
                    help="keep this many backup directories, deleting older ones after a successful apply; 0 keeps all (default 10)")
    common(sp)
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("rollback", help="restore a backup taken by apply")
    sp.add_argument("backup_dir")
    sp.add_argument("--force-version", action="store_true")
    common(sp)
    sp.set_defaults(func=cmd_rollback)

    sp = sub.add_parser("schema", help="print the JSON Schema of the file format")
    sp.set_defaults(func=cmd_schema)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except Fail as e:
        print(redact(f"as_config.py: {e}"), file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
