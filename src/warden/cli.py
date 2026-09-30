"""Command-line interface for Warden.

    warden baseline [--fake]     reproduce the injection with no governance
    warden governed [--fake]     same injection, blocked by Warden
    warden drift                 the anomaly detector (second line of defense)
    warden trace [TASK] [--fake] narrated, step-by-step debug flow
    warden eval                  attack-containment + false-quarantine numbers
    warden audit-verify FILE     check an audit log's hash chain on disk
    warden policy check FILE     validate a policy file and show what it grants

--fake uses the offline, deterministic model (no API key, no cost). It is also
enabled by the WARDEN_FAKE_LLM=1 environment variable.
"""

from __future__ import annotations

import argparse
import os


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [
        ("baseline", "reproduce the injection with no governance"),
        ("governed", "same injection, blocked by Warden"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--fake", action="store_true", help="use the offline deterministic model")

    sub.add_parser("drift", help="the anomaly detector (no LLM needed)")

    p = sub.add_parser("trace", help="narrated, step-by-step debug flow")
    p.add_argument("task", nargs="?", default="summarize", choices=["summarize", "process_refund"])
    p.add_argument("--fake", action="store_true", help="use the offline deterministic model")

    sub.add_parser("eval", help="attack-containment + false-quarantine numbers (no LLM needed)")

    p = sub.add_parser("audit-verify", help="check an audit log's hash chain on disk")
    p.add_argument("path", help="path to an audit/<session>.jsonl file")

    p = sub.add_parser("policy", help="policy file tools")
    policy_sub = p.add_subparsers(dest="policy_command", required=True)
    pc = policy_sub.add_parser("check", help="validate a policy file and show what it grants")
    pc.add_argument("path", help="path to a policy .toml file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Must set the env var BEFORE importing modules that read settings at import.
    if getattr(args, "fake", False):
        os.environ["WARDEN_FAKE_LLM"] = "1"

    if args.command == "baseline":
        from warden.demos import baseline

        baseline.main()
    elif args.command == "governed":
        from warden.demos import governed

        governed.main()
    elif args.command == "drift":
        from warden.demos import drift

        drift.main()
    elif args.command == "trace":
        from warden.demos import trace

        trace.main(args.task)
    elif args.command == "eval":
        from warden.evaluation import harness

        harness.main()
    elif args.command == "audit-verify":
        from warden.governance.audit import AuditLog

        ok, detail = AuditLog.verify_file(args.path)
        print(f"{'OK' if ok else 'FAIL'}: {args.path}: {detail}")
        return 0 if ok else 1
    elif args.command == "policy":
        return _policy_check(args.path)
    return 0


def _policy_check(path: str) -> int:
    from warden.governance.policy_loader import PolicyError, load_policy

    try:
        policy = load_policy(path)
    except (PolicyError, OSError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"OK: {path}  ({len(policy.tools)} tools, {len(policy.tasks)} tasks)")
    for task, roles in policy.tasks.items():
        default = "  (default)" if task == policy.default_task else ""
        print(f"\ntask {task}{default}")
        for role, templates in roles.items():
            grants = "; ".join(_describe(t) for t in templates) or "(nothing)"
            print(f"  {role:<16} {grants}")
    return 0


def _describe(template: dict) -> str:
    parts = [f"{template['tool']}[{template['scope']}]"]
    for name, rule in template.get("params", {}).items():
        if "allow" in rule:
            parts.append(f"{name} in {rule['allow']}")
        if "min" in rule or "max" in rule:
            parts.append(f"{name} in [{rule.get('min', '-inf')}, {rule.get('max', 'inf')}]")
    parts.append(f"ttl={template['ttl']:g}s")
    if "max_uses" in template:
        parts.append(f"uses={template['max_uses']}")
    return " ".join(parts)


if __name__ == "__main__":
    raise SystemExit(main())
