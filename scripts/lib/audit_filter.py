"""Compare auditor output against the accepted advisory file.

Reads auditor json on stdin and the accepted ids from the ACCEPTED environment
variable, one id per line. Exits non-zero when an advisory is reported that the
file does not list. Accepted advisories are printed as skipped, so an exemption
stays visible in the gate output instead of disappearing from it.

The single argument selects the auditor: cargo or npm.
"""

import json
import os
import sys

NPM_BLOCKING = ("high", "critical")


def accepted_ids():
    return {
        line.strip()
        for line in os.environ.get("ACCEPTED", "").splitlines()
        if line.strip()
    }


def cargo_findings(doc):
    for entry in doc.get("vulnerabilities", {}).get("list", []):
        advisory = entry.get("advisory", {})
        package = entry.get("package", {})
        yield {
            "id": advisory.get("id", "unknown"),
            "package": package.get("name", "unknown"),
            "version": package.get("version", ""),
            # cargo audit reports a cvss vector and no severity word, so the
            # vector is what gets printed rather than a rating invented here.
            "severity": advisory.get("cvss") or "unrated",
            "title": advisory.get("title", ""),
            "blocking": True,
        }


def npm_findings(doc):
    for name, node in doc.get("vulnerabilities", {}).items():
        for via in node.get("via", []):
            if not isinstance(via, dict):
                continue
            severity = via.get("severity", node.get("severity", "unrated"))
            yield {
                "id": via.get("url", "").rsplit("/", 1)[-1] or "unknown",
                "package": via.get("name", name),
                "version": node.get("range", ""),
                "severity": severity,
                "title": via.get("title", ""),
                "blocking": severity in NPM_BLOCKING,
            }


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    if which == "cargo":
        collect = cargo_findings
    elif which == "npm":
        collect = npm_findings
    else:
        print("usage: audit_filter.py cargo|npm", file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("no auditor output to read", file=sys.stderr)
        return 1
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        print("auditor output was not json: %s" % exc, file=sys.stderr)
        return 1

    ok = accepted_ids()
    if not ok:
        print("the accepted advisory list reached this filter empty", file=sys.stderr)
        return 1

    findings = list(collect(doc))
    seen, skipped, unlisted = set(), [], []
    for f in findings:
        if not f["blocking"] or f["id"] in seen:
            continue
        seen.add(f["id"])
        (skipped if f["id"] in ok else unlisted).append(f)

    for f in sorted(skipped, key=lambda x: x["id"]):
        print("accepted, skipped: %s  %s %s" % (f["id"], f["package"], f["version"]))

    below = len({f["id"] for f in findings if not f["blocking"]})
    if below:
        print("%d advisory below high severity reported, not blocking" % below)

    if unlisted:
        print(
            "%d advisory not listed in scripts/accepted-advisories.txt:" % len(unlisted),
            file=sys.stderr,
        )
        for f in sorted(unlisted, key=lambda x: x["id"]):
            print(
                "    %s  %s %s  %s  %s"
                % (f["id"], f["package"], f["version"], f["severity"], f["title"][:70]),
                file=sys.stderr,
            )
        return 1

    print("%d blocking advisory reported, every one accepted" % len(seen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
