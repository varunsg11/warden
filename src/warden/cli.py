"""Command-line interface for Warden.

    warden baseline [--fake]     reproduce the injection with no governance
    warden governed [--fake]     same injection, blocked by Warden
    warden drift                 the anomaly detector (second line of defense)
    warden trace [TASK] [--fake] narrated, step-by-step debug flow
    warden eval                  attack-containment + false-quarantine numbers

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
