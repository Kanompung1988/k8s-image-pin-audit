# Findings

| ID | Severity | Condition | Action |
|---|---|---|---|
| IP001 | HIGH | Explicit `:latest` or no tag/digest | Resolve a trusted digest to make rollout reproducible. |
| IP002 | MEDIUM | A normal, mutable tag without digest | Pin to verified digest when appropriate. |
| IP003 | MEDIUM | `imagePullPolicy: Never` | Ensure image is preloaded and policy intentional. |
| IP004 | HIGH | Malformed image digest or name | Fix image reference syntax; verify with registry. |
| IP005 | MEDIUM | Mutable tag with `IfNotPresent` | Review node cache/version divergence. |
| IP006 | HIGH | Unsupported pull policy | Use Always, IfNotPresent, or Never. |
| IP007 | HIGH | Missing or malformed container/image | Fix manifest definition. |
| IP008 | MEDIUM | Unsupported document/collection shape or truncated entries | Review manually; static scan intentionally incomplete. |

Tags and digests can coexist in an image reference; a syntactically valid digest pin determines what content is pulled. The scanner cannot prove digest authenticity or publisher identity and does not evaluate unrendered Helm/Kustomize templates.
