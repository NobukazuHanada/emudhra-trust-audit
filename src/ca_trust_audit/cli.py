"""Command line interface.

    ca-trust-audit endpoint [--format text|json|sarif] [--network-test HOST]
    ca-trust-audit project [PATH] [--format ...] [--scan-bundle FILE]
    ca-trust-audit data [--verify] [--write-checksums]
    ca-trust-audit explain FINDING_ID

Exit codes
    0  nothing to do: no indicator found, or already remediated
    1  review required: something could not be assessed, or needs a human
    2  action required: a known indicator with a concrete remediation step
    3  the audit itself failed (bad data, unreadable input, internal error)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, datafiles, endpoint, explanations, project
from . import report as report_module
from .endpoint.context import EndpointContext
from .model import EXIT_ERROR, Report
from .project.scan import ProjectContext
from .redact import Redactor
from .util import CommandRunner, DisabledRunner

FORMATS = ("text", "json", "sarif")


class AuditParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid command arguments; use --help")


def build_parser() -> argparse.ArgumentParser:
    parser = AuditParser(
        prog="ca-trust-audit",
        description=(
            "Read-only audit for compromised certificate-authority trust. Makes no change to the "
            "system by default. Network tests, executable probes and report writes are explicit opt-ins."
        ),
        epilog="Exit codes: 0 nothing to do, 1 review required, 2 action required, 3 audit error.",
    )
    parser.add_argument("--version", action="version", version="ca-trust-audit %s" % __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--format", choices=FORMATS, default="text", help="output format (default: text)"
        )
        target.add_argument(
            "--output", metavar="FILE", help="write the report to FILE instead of stdout"
        )
        target.add_argument(
            "--data-dir", metavar="DIR", help="directory holding the indicator data"
        )
        target.add_argument(
            "--allow-unverified-data",
            action="store_true",
            help="continue even if data/checksums.json does not match (not recommended)",
        )

    endpoint_parser = subparsers.add_parser(
        "endpoint", help="audit this machine's trust stores, runtimes and clients"
    )
    add_common(endpoint_parser)
    endpoint_parser.add_argument(
        "--bundle",
        metavar="PATH",
        action="append",
        default=[],
        help="additional CA bundle file or directory to scan (repeatable)",
    )
    endpoint_parser.add_argument(
        "--network-test",
        metavar="HOST[:PORT]",
        default="",
        help="opt in to online TLS probes against HOST; discloses this machine's address to it",
    )
    endpoint_parser.add_argument(
        "--commands",
        action="store_true",
        help="opt in to local executable probes; only use trusted installed tools",
    )
    endpoint_parser.add_argument(
        "--no-commands",
        action="store_true",
        help="read files only; run no external command at all",
    )
    endpoint_parser.add_argument(
        "--no-user-stores",
        action="store_true",
        help="skip per-user trust stores (login keychain, CurrentUser stores)",
    )
    endpoint_parser.add_argument(
        "--fs-root",
        metavar="DIR",
        help="treat DIR as the filesystem root (for testing against a fixture tree)",
    )

    project_parser = subparsers.add_parser(
        "project", help="audit a repository's dependencies, bundles, containers and TLS settings"
    )
    add_common(project_parser)
    project_parser.add_argument(
        "path", nargs="?", default=".", help="project directory (default: .)"
    )
    project_parser.add_argument(
        "--no-containers", action="store_true", help="skip container definition checks"
    )
    project_parser.add_argument(
        "--scan-bundle", metavar="FILE", help="additionally scan one CA bundle file by path"
    )

    data_parser = subparsers.add_parser("data", help="inspect or re-checksum the indicator data")
    data_parser.add_argument(
        "--data-dir", metavar="DIR", help="directory holding the indicator data"
    )
    data_parser.add_argument(
        "--verify", action="store_true", help="verify checksums and schemas (default)"
    )
    data_parser.add_argument(
        "--write-checksums",
        action="store_true",
        help="maintainer action: rewrite data/checksums.json from the files on disk",
    )
    data_parser.add_argument("--format", choices=("text", "json"), default="text")

    explain_parser = subparsers.add_parser("explain", help="explain a finding id")
    explain_parser.add_argument("finding_id", nargs="?", help="for example ENDPOINT-SPKI-TRUSTED")
    explain_parser.add_argument("--list", action="store_true", help="list every finding id")
    explain_parser.add_argument(
        "--data-dir", metavar="DIR", help="directory holding the indicator data"
    )

    return parser


def _emit(text: str, output: Optional[str]) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print("report written", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _load_data(args: argparse.Namespace) -> datafiles.DataBundle:
    data = datafiles.load(getattr(args, "data_dir", None))
    if data.schema_problems or (
        data.checksum_status != "verified" and not getattr(args, "allow_unverified_data", False)
    ):
        raise datafiles.DataError("indicator data failed validation")
    return data


def _finish(report: Report, args: argparse.Namespace) -> int:
    from .redact import sanitize_report

    sanitize_report(report, Redactor.from_env(dict(os.environ)))
    _emit(report_module.render(report, args.format), args.output)
    if report.errors and not getattr(args, "allow_unverified_data", False):
        return EXIT_ERROR
    return report.exit_code


def run_endpoint(args: argparse.Namespace) -> int:
    data = _load_data(args)
    env = dict(os.environ)
    args.no_commands = args.no_commands or not args.commands
    runner: CommandRunner = DisabledRunner(env=env) if args.no_commands else CommandRunner(env=env)
    fs_root = Path(args.fs_root) if args.fs_root else None
    ctx = EndpointContext(
        data=data,
        env=env,
        runner=runner,
        fs_root=fs_root,
        offline=not args.network_test,
        network_host=args.network_test,
        extra_bundles=[Path(value) for value in args.bundle],
        include_user_stores=not args.no_user_stores,
        redactor=Redactor.from_env(env, windows=os.name == "nt"),
    )
    if args.no_commands:
        ctx.notes.append(
            "External commands are disabled: anything that needs one "
            "(keychain enumeration, package versions, runtime versions) is reported as unable to assess."
        )
    return _finish(endpoint.audit(ctx), args)


def run_project(args: argparse.Namespace) -> int:
    data = _load_data(args)
    root = Path(args.path).expanduser()
    if not root.is_dir():
        raise OSError("project directory is unavailable")
    ctx = ProjectContext(
        root=root,
        data=data,
        env=dict(os.environ),
        include_containers=not args.no_containers,
    )
    return _finish(project.audit(ctx, scan_bundle=args.scan_bundle), args)


def run_data(args: argparse.Namespace) -> int:
    if args.write_checksums:
        directory = datafiles.find_data_dir(args.data_dir)
        target = datafiles.write_checksums(directory)
        print("wrote %s" % target)
        return 0
    data = datafiles.load(args.data_dir, validate_schema=True)
    payload = {
        "data_dir": str(data.data_dir),
        "checksum_status": data.checksum_status,
        "checksum_problems": data.checksum_problems,
        "schema_problems": data.schema_problems,
        "datasets": data.describe_sources(),
        "compromised_spki_count": len(data.compromised_spki),
        "related_root_count": len(data.related_root_names),
        "insecure_rule_count": len(data.insecure_rules.get("rules", [])),
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print("data directory: %s" % payload["data_dir"])
        print("checksums:      %s" % payload["checksum_status"])
        for problem in data.checksum_problems:
            print("  ! %s" % problem)
        for problem in data.schema_problems:
            print("  ! schema: %s" % problem)
        for dataset in payload["datasets"]:
            print(
                "dataset %-18s version %s as of %s"
                % (dataset["id"], dataset["data_version"], dataset["as_of"])
            )
            for source in dataset["sources"]:
                print("    source: %s" % source)
        print("compromised SPKIs: %d" % payload["compromised_spki_count"])
        print("related roots:     %d" % payload["related_root_count"])
        print("insecure TLS rules:%d" % payload["insecure_rule_count"])
    if data.checksum_status != "verified" or data.schema_problems:
        return EXIT_ERROR
    return 0


def run_explain(args: argparse.Namespace) -> int:
    data: Optional[datafiles.DataBundle]
    try:
        data = datafiles.load(args.data_dir)
    except datafiles.DataError:
        data = None
    if args.list or not args.finding_id:
        ids: List[str] = explanations.known_ids()
        if data is not None:
            ids += ["PROJECT-%s" % rule["id"] for rule in data.insecure_rules.get("rules", [])]
        for finding_id in sorted(set(ids)):
            print(finding_id)
        return 0
    explanation = explanations.lookup(args.finding_id, data)
    if explanation is None:
        print("unknown finding id: %s (try --list)" % args.finding_id, file=sys.stderr)
        return EXIT_ERROR
    print(explanations.render(args.finding_id, explanation))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except ValueError:
        print(json.dumps({"exit_code": EXIT_ERROR, "errors": ["invalid arguments; use --help"]}))
        return EXIT_ERROR
    handlers = {
        "endpoint": run_endpoint,
        "project": run_project,
        "data": run_data,
        "explain": run_explain,
    }
    try:
        return handlers[args.command](args)
    except (
        datafiles.DataError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        KeyboardInterrupt,
    ) as error:
        # Never serialize exception messages: they can contain paths or input secrets.
        payload = {"exit_code": EXIT_ERROR, "errors": ["audit failed: " + type(error).__name__]}
        print(json.dumps(payload))
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
