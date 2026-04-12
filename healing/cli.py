from __future__ import annotations

import argparse
import json

from .status_service import get_healing_service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run DARKPULSE healing monitor tasks locally.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("discover", help="Discover monitorable collector scripts.")
    subparsers.add_parser("summary", help="Show the current healing summary.")

    run_parser = subparsers.add_parser("run", help="Run healing checks.")
    run_parser.add_argument("--limit", type=int, default=None)
    run_parser.add_argument("--collector", default="")
    run_parser.add_argument("--mode", default="default", choices=["default", "full", "collector", "single"])
    run_parser.add_argument("--auto-heal", action="store_true")
    run_parser.add_argument("--apply", action="store_true", help="Allow repair application after high-confidence checks.")

    check_parser = subparsers.add_parser("check", help="Run a single script check.")
    check_parser.add_argument("script_id")

    repair_parser = subparsers.add_parser("repair", help="Generate a repair preview for one script.")
    repair_parser.add_argument("script_id")

    apply_parser = subparsers.add_parser("apply-repair", help="Apply the latest repair candidate for one script.")
    apply_parser.add_argument("script_id")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    service = get_healing_service()

    if args.command == "discover":
        result = service.discover_targets(force=True)
    elif args.command == "summary":
        result = service.get_summary()
    elif args.command == "run":
        result = service.run_monitor(
            limit=args.limit,
            collector_name=args.collector or None,
            mode=args.mode,
            auto_heal=bool(args.auto_heal and args.apply),
            dry_run_repair=not args.apply,
        )
    elif args.command == "check":
        result = service.run_target_check(args.script_id)
    elif args.command == "repair":
        result = service.generate_repair(args.script_id)
    elif args.command == "apply-repair":
        result = service.apply_repair(args.script_id)
    else:
        parser.error("Unknown command")
        return

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
