#!/usr/bin/env python3
# ci/verify-config-schema.py - CCU-SEC-DSN-CR-005 §5.3/§9
#
# Side-effect-free checker for the complete unified sec.yaml. Runs the
# versioned JSON Schema (Draft-07) and adds cross-field / secret checks that
# JSON Schema cannot express:
#   * no top-level common:
#   * no secret/provisioning fields, no key_files, no /tmp security store
#   * one process uses exactly one vsomeip application
#   * method IDs unique in 0x0001-0x7FFF (event segment stays reserved)
#   * no real VIN / device-unique values
#   * --profile release additionally rejects the safe install placeholder
#     (unconfigured) and the NON_PRODUCTION software fixture
#
# No network, no device access, no secret reads, no writes.
# Usage: verify-config-schema.py [--schema PATH] [--profile default|release]
#                                [--timeout N] <sec.yaml> [...]
# Exit: 0 = pass, 1 = validation failure.

import argparse
import re
import signal
import sys
from pathlib import Path

import yaml
import jsonschema


VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
FORBIDDEN_KEYS = {
    "key_files",
    "key_file",
    "keyfiles",
    "storage_path",
    "storage-path",
    "vin",
    "device_sn",
    "device_id",
    "device-id",
    "password",
    "secret",
    "secrets",
    "token",
    "private_key",
    "private-key",
    "key_material",
    "session_key",
    "session-key",
    "seed",
    "nonce",
    "credentials",
    "cert",
    "certificate",
    "provisioning",
}
METHOD_MIN = 0x0001
METHOD_MAX = 0x7FFF
RELEASE_FORBIDDEN_HSM_TYPES = {"unconfigured", "software"}


def walk(node, path, errors):
    if isinstance(node, dict):
        for key, value in node.items():
            key_s = str(key)
            if key_s.lower() in FORBIDDEN_KEYS:
                errors.append(f"{path}.{key_s}: forbidden secret/provisioning key")
            walk(value, f"{path}.{key_s}", errors)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            walk(value, f"{path}[{idx}]", errors)
    elif isinstance(node, str):
        if VIN_RE.match(node):
            errors.append(f"{path}: value looks like a real VIN")
        if node == "/tmp" or node.startswith("/tmp/"):
            errors.append(f"{path}: /tmp must not be used as a security store")


def cross_field_checks(data, profile, errors):
    sec = data.get("sec")
    if not isinstance(sec, dict):
        return

    someip = sec.get("someip", {})
    if isinstance(someip, dict):
        app = someip.get("application_name")
        if app not in (None, "ccu-sec"):
            errors.append(
                f"sec.someip.application_name={app!r} must be 'ccu-sec' "
                "(one process must use one vsomeip application)")

        methods = someip.get("methods", {})
        seen = set()
        if isinstance(methods, dict):
            for name, entry in methods.items():
                mid = entry.get("method_id") if isinstance(entry, dict) else None
                if isinstance(mid, int):
                    if mid < METHOD_MIN or mid > METHOD_MAX:
                        errors.append(
                            f"sec.someip.methods.{name}.method_id={mid} "
                            "outside method segment 0x0001-0x7FFF")
                    if mid in seen:
                        errors.append(
                            f"duplicate method_id {mid} at sec.someip.methods.{name}")
                    seen.add(mid)

    if profile == "release":
        se_hsm = sec.get("se_hsm", {})
        hsm_type = se_hsm.get("type") if isinstance(se_hsm, dict) else None
        if hsm_type in RELEASE_FORBIDDEN_HSM_TYPES:
            errors.append(
                f"sec.se_hsm.type={hsm_type!r} is not allowed in a release "
                "profile (requires an approved production SE/HSM adapter)")


class CheckerTimeout(Exception):
    pass


def _on_alarm(_signum, _frame):
    raise CheckerTimeout()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", default=None)
    ap.add_argument("--profile", choices=["default", "release"], default="default")
    ap.add_argument("--timeout", type=int, default=30,
                    help="hard wall-clock timeout in seconds (default 30)")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    if args.timeout > 0:
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(args.timeout)

    repo = Path(__file__).resolve().parent.parent
    schema_path = (Path(args.schema) if args.schema
                   else repo / "config" / "schema" / "sec.schema.yaml")

    try:
        schema = yaml.safe_load(schema_path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        print(f"[FAIL] cannot load schema {schema_path}: {exc}", file=sys.stderr)
        return 1

    validator = jsonschema.Draft7Validator(schema)
    status = 0

    for file_name in args.files:
        path = Path(file_name)
        errors = []
        try:
            data = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError) as exc:
            print(f"[FAIL] {path}: cannot read/parse YAML: {exc}", file=sys.stderr)
            status = 1
            continue

        if isinstance(data, dict) and "common" in data:
            errors.append("top-level 'common:' is forbidden in sec.yaml")

        for err in sorted(validator.iter_errors(data),
                          key=lambda e: list(e.absolute_path)):
            loc = ".".join(str(p) for p in err.absolute_path) or "(root)"
            errors.append(f"schema {loc}: {err.message}")

        walk(data, "root", errors)
        if isinstance(data, dict):
            cross_field_checks(data, args.profile, errors)

        if errors:
            status = 1
            print(f"[FAIL] {path} (profile={args.profile})", file=sys.stderr)
            for err in errors:
                print(f"       - {err}", file=sys.stderr)
        else:
            print(f"[OK]   {path} (profile={args.profile})")

    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CheckerTimeout:
        print("[FAIL] config checker timed out", file=sys.stderr)
        sys.exit(1)
