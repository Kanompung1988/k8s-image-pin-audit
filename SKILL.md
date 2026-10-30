---
name: k8s-image-pin-audit
description: Review local Kubernetes Pod and workload YAML for unpinned image tags, latest images, malformed digests and risky imagePullPolicy combinations before deploy. Use with Claude Code or Codex for offline rollout reproducibility checks.
license: MIT
compatibility: Python 3.10+ with PyYAML 6.x; local YAML/JSON manifests only. No cluster access, image pulls, registry access, or execution.
metadata:
  author: AREAZERO Skill Lab
  version: "1.0.0"
---

# Verify Kubernetes image references before deployment

## Trigger
Use during code review of Kubernetes manifests, Helm/Kustomize-rendered YAML or a pull request changing Pod images. Especially useful when CI uses `:latest`, non-pinned tags or unusual pull policies.

## Non-trigger
Do not use to verify image signatures/provenance, identify actual digest contents, access Kubernetes cluster, prove node cache state, evaluate admission controllers or inspect Helm templates before rendering them. This scanner is static and read-only.

## Procedure
1. Provide a synthetic or approved **rendered** Kubernetes YAML/JSON file. Do not include Secrets objects, tokens or real private registry credentials.
2. Run `python -m pip install -r requirements.txt`, then `python scripts/audit.py deploy.yaml --format markdown --fail-on high`. PyYAML safe loading is bounded to 1 MiB and 500 top-level documents.
3. Review `IP001`–`IP008` in [rule reference](references/RULES.md). A `:latest` tag and an implicit latest are different presentations of an unpinned image; the scanner correctly separates registry port from final image tag.
4. For repeatable deploys pin to an actual trusted content digest such as `image@sha256:<real 64 hex digest>` **retrieved from your trusted registry** and verify provenance separately. Never copy a synthetic digest into production.
5. Remember Kubernetes sets default imagePullPolicy on object creation and **does not automatically revise it** when an existing PodTemplate image tag changes. Compare live object policy through authorized cluster tools when appropriate.
6. Re-run scanner and tests; record rule IDs and limitations. Do not mutate Kubernetes resources as part of this Skill.

## Local demo
`python scripts/audit.py examples/safe.yaml --format json` exits 0; `python scripts/audit.py examples/review.yaml --format json --fail-on none` prints synthetic findings but exits 0; `--fail-on high` returns 2 for `latest`. Run `python -m unittest discover -s tests -v`.

## Safety
Static source review only, no registry lookups. It does not resolve tag immutability guarantees, node caching, image admission policies, aliases or full manifest rendering. The tool intentionally does not print complete image strings or payload contents.
