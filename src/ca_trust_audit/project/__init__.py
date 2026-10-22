"""Project audit: what does *this repository* trust, pin and switch off?"""

from __future__ import annotations

import datetime
from typing import Optional

from .. import __version__
from ..model import Report
from . import checks, content
from .scan import ProjectContext

__all__ = ["ProjectContext", "audit"]


def audit(ctx: ProjectContext, *, scan_bundle: Optional[str] = None) -> Report:
    report = Report(
        tool="project audit",
        tool_version=__version__,
        scope="project (%s)" % (ctx.redactor.path(ctx.root) if ctx.redactor else str(ctx.root)),
        started_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    report.data_sources = ctx.data.describe_sources()

    if ctx.data.checksum_status != "verified":
        report.errors.append(
            "data integrity: %s (%s)"
            % (ctx.data.checksum_status, "; ".join(ctx.data.checksum_problems) or "no detail")
        )
    for problem in ctx.data.schema_problems:
        report.errors.append("data schema: %s" % problem)

    files = ctx.walk()
    dependencies = checks.collect_dependencies(ctx)
    total, pinned = checks.dependency_summary(ctx, dependencies)
    report.context = {
        "files_walked": len(files),
        "dependencies_parsed": total,
        "pinned_versions": pinned,
        "containers_included": ctx.include_containers,
    }

    report.extend(checks.dependency_findings(ctx, dependencies))
    report.extend(content.bundle_findings(ctx))
    report.extend(content.insecure_findings(ctx))
    report.extend(content.container_findings(ctx))
    report.extend(content.ci_findings(ctx))
    report.extend(checks.inventory_findings(ctx, dependencies))
    if scan_bundle:
        report.add(content.external_bundle_finding(ctx, scan_bundle))

    report.notes.append(
        "Read-only: no file in this project was created, modified or deleted, no dependency was "
        "installed or resolved, and nothing was sent anywhere."
    )
    if ctx.ignored:
        # An exclusion is never silent: it is stated whether or not an inventory
        # finding was produced.
        report.notes.append(
            "%d file(s) were excluded by .ca-trust-audit-ignore and not examined: %s"
            % (
                len(ctx.ignored),
                ", ".join(ctx.ignored[:25]) + (" ..." if len(ctx.ignored) > 25 else ""),
            )
        )
    report.notes.append(
        "Lock files describe what should be installed. What is actually installed in a virtual "
        "environment, node_modules tree or built image can differ; those directories are excluded from "
        "the walk by data/rules/insecure-tls.json."
    )
    report.notes.append(
        "Only variable names and repository-relative paths are reported. No environment variable value, "
        "token, password or private key is read into this report."
    )
    report.notes.extend(ctx.notes)
    return report
