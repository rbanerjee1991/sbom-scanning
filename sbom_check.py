#!/usr/bin/env python3
"""Minimal SBOM check (CycloneDX JSON).

Flags components that have no version, no licence, or a licence on the deny list.
Usage: python3 sbom_check.py sample/sbom.cdx.json
Exit code 1 when any finding is reported, so it can fail a CI job.
"""
import json
import sys

DENY_LICENSES = {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"}


def licences(component):
    ids = []
    for entry in component.get("licenses", []):
        lic = entry.get("license", {})
        ids.append(lic.get("id") or lic.get("name") or entry.get("expression", ""))
    return [i for i in ids if i]


def check(path):
    with open(path, encoding="utf-8") as fh:
        sbom = json.load(fh)
    findings = []
    for comp in sbom.get("components", []):
        name = comp.get("name", "<unnamed>")
        if not comp.get("version"):
            findings.append(f"{name}: missing version")
        lics = licences(comp)
        if not lics:
            findings.append(f"{name}: missing licence")
        for lic in lics:
            if lic in DENY_LICENSES:
                findings.append(f"{name}: licence {lic} is not allowed")
    return findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: sbom_check.py <cyclonedx.json>")
    results = check(sys.argv[1])
    for line in results:
        print(f"FINDING  {line}")
    print(f"{len(results)} finding(s)")
    sys.exit(1 if results else 0)
