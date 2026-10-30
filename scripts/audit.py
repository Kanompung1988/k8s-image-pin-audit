#!/usr/bin/env python3
"""Offline Kubernetes image reference/pull policy review; does not contact registries."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

MAX_BYTES = 1024 * 1024
MAX_DOCUMENTS = 500
LEVEL = {"low": 1, "medium": 2, "high": 3}
DIGEST = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def spec_from(obj: dict) -> dict | None:
    kind = obj.get("kind")
    spec = obj.get("spec", {})
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = spec.get("jobTemplate")
        job_spec = job.get("spec") if isinstance(job, dict) else None
        tmpl = job_spec.get("template") if isinstance(job_spec, dict) else None
    elif kind in {"Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet", "ReplicationController"}:
        tmpl = spec.get("template", {})
    else:
        return None
    if not isinstance(tmpl, dict):
        return None
    podspec = tmpl.get("spec")
    return podspec if isinstance(podspec, dict) else None


def parse_image(image: str) -> dict:
    """Extract terminal tag without confusing a registry's :port with an image tag."""
    if not isinstance(image, str) or not image.strip() or image.strip() != image:
        return {"error": "Missing or malformed image reference."}
    if image.count("@") > 1:
        return {"error": "Multiple digest separators."}
    base, mark, digest = image.partition("@")
    if mark and not DIGEST.fullmatch(digest):
        return {"error": "Digest must be sha256 followed by 64 hexadecimal characters."}
    leaf = base.rsplit("/", 1)[-1]
    if not leaf:
        return {"error": "Image reference has an empty final component."}
    tag = leaf.rsplit(":", 1)[-1] if ":" in leaf else None
    if tag is not None and not TAG.fullmatch(tag):
        return {"error": "Image tag is not syntactically valid."}
    if not base or " " in base or any(x in base for x in "\r\n\t"):
        return {"error": "Image name contains invalid whitespace."}
    return {"pinned": bool(mark), "tag": tag or "latest", "implicit": tag is None, "has_tag": tag is not None}


def examine_container(container: dict, location: str) -> list[dict]:
    findings: list[dict] = []
    def emit(rule, severity, message):
        findings.append({"rule": rule, "severity": severity, "location": location, "message": message})
    if not isinstance(container, dict):
        emit("IP007", "high", "Container entry is not an object.")
        return findings
    image = container.get("image")
    parsed = parse_image(image)
    if "error" in parsed:
        emit("IP007" if not image else "IP004", "high", parsed["error"])
    elif not parsed["pinned"] and parsed["tag"] == "latest":
        emit("IP001", "high", "Image uses implicit or explicit latest rather than a content digest.")
    elif not parsed["pinned"]:
        emit("IP002", "medium", "Tag is mutable; consider a sha256 digest for repeatable rollout.")
    policy = container.get("imagePullPolicy")
    if policy is not None and (not isinstance(policy, str) or policy not in {"Always", "IfNotPresent", "Never"}):
        emit("IP006", "high", "Unknown imagePullPolicy value; Kubernetes accepts Always, IfNotPresent, Never.")
    elif policy == "Never":
        emit("IP003", "medium", "Never requires the exact image to be preloaded on every eligible node.")
    elif policy == "IfNotPresent" and not parsed.get("pinned", False):
        emit("IP005", "medium", "IfNotPresent with a mutable tag can reuse different cached image versions across nodes.")
    return findings


def analyze(documents: list) -> dict:
    issues: list[dict] = []
    processed = 0
    inspected = 0
    def emit(rule, severity, location, message):
        issues.append({"rule": rule, "severity": severity, "location": location, "message": message})
    def visit(obj, n, stack=0):
        nonlocal processed, inspected
        if stack > 4:
            emit("IP008", "medium", f"document:{n}", "Nested List objects exceed supported depth.")
            return
        if not isinstance(obj, dict):
            emit("IP008", "medium", f"document:{n}", "Non-object YAML document skipped.")
            return
        if obj.get("kind") == "List":
            items = obj.get("items")
            if not isinstance(items, list):
                emit("IP008", "medium", f"document:{n}", "List.items must be an array.")
                return
            for i, item in enumerate(items[:500]):
                visit(item, f"{n}/items:{i}", stack+1)
            if len(items) > 500:
                emit("IP008", "medium", f"document:{n}", "List items truncated at 500.")
            return
        podspec = spec_from(obj)
        if podspec is None:
            return
        processed += 1
        kind = str(obj.get("kind", "Unknown"))[:64]
        meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
        # Do not emit raw metadata values; trim and escape any malformed path-like separators.
        name = re.sub(r"[^a-zA-Z0-9._-]", "_", str(meta.get("name", "unnamed")))[:100]
        loc = f"doc:{n}:{kind}/{name}"
        for key in ("initContainers", "containers", "ephemeralContainers"):
            arr = podspec.get(key, [])
            if not isinstance(arr, list):
                emit("IP008", "medium", f"{loc}:{key}", "Container collection is not a list.")
                continue
            for i, container in enumerate(arr[:500]):
                inspected += 1
                issues.extend(examine_container(container, f"{loc}:{key}[{i}]"))
            if len(arr) > 500:
                emit("IP008", "medium", f"{loc}:{key}", "Container list truncated at 500.")
    for i, document in enumerate(documents):
        if document is not None:
            visit(document, i)
    return {"workloads_checked": processed, "containers_checked": inspected, "findings": sorted(issues, key=lambda x: (x["location"], x["rule"]))}


def load_documents(path: Path) -> list:
    if yaml is None:
        raise ValueError("PyYAML is missing: pip install -r requirements.txt")
    if not path.is_file() or path.is_symlink():
        raise ValueError("Expected a regular input YAML/JSON file (no symlink)")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("File exceeds 1 MiB limit")
    with path.open("r", encoding="utf-8") as fp:
        docs = list(yaml.safe_load_all(fp))
    if len(docs) > MAX_DOCUMENTS:
        raise ValueError("More than 500 YAML documents")
    return docs


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only Kubernetes container image pinning audit")
    p.add_argument("file", type=Path, help="Local Kubernetes YAML/JSON manifest")
    p.add_argument("--format", choices=("json", "markdown"), default="markdown")
    p.add_argument("--fail-on", choices=("none", "medium", "high"), default="high")
    args = p.parse_args(argv)
    try:
        result = analyze(load_documents(args.file))
    except (OSError, ValueError, UnicodeError, yaml.YAMLError if yaml else ValueError):
        print(json.dumps({"error": "INVALID_INPUT", "message": "Manifest unavailable, unsafe, too large or invalid YAML/JSON."}), file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"# Kubernetes image pin audit\n\nWorkloads: {result['workloads_checked']} | Containers: {result['containers_checked']}\n")
        for f in result["findings"]:
            print(f"- **{f['severity'].upper()} {f['rule']}** `{f['location']}` — {f['message']}")
    threshold = LEVEL.get(args.fail_on, 99)
    return 2 if any(LEVEL[f["severity"]] >= threshold for f in result["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
