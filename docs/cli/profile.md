# tms profile

Print a built-in artifact-availability profile definition.

## Synopsis

```bash
tms profile <name> [flags]
```

## Description

`tms profile` prints one of the three built-in `ArtifactAvailabilityProfile` definitions: which artifact types that profile assumes are available, and which PDLC stages are permitted — or explicitly not analyzable, with a stated reason — under it. This is static data; no model file is involved. Use it to check ahead of time whether [`tms analyze --stage <s> --profile <p>`](analyze.md) will be allowed before resolving any real inputs.

## Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--help`, `-h` | Show help |

## Examples

### Default Output

```bash
tms profile first-party
```

Output:
```
Profile: first-party
Full access: source code, deployment configuration, and runtime telemetry for a product you own and operate.

Available artifact types:
  - product-spec
  - technical-spec
  - source-tree
  - dependency-manifest
  - sbom
  - iac
  - deployment-manifest
  - runtime-endpoint
  - telemetry
  - incident

Permitted stages:
  - product-definition
  - builder-definition
  - implementation
  - deployment
  - builder-operations
  - product-operations
```

`first-party` permits all six stages — the only profile that does.

### A Restricted Profile

```bash
tms profile open-source
```

```
Profile: open-source
...

Not analyzable:
  - deployment: no access to deployment configuration for a dependency you don't operate
  - builder-operations: no access to runtime telemetry for a dependency you don't operate
  - product-operations: no access to product telemetry for a dependency you don't operate
```

### JSON Output

```bash
tms profile third-party --json
```

```json
{
  "profile": "third-party",
  "description": "...",
  "availableArtifactTypes": ["technical-spec", "source-tree", "dependency-manifest", "sbom"],
  "permittedStages": ["builder-definition", "implementation"],
  "notAnalyzableStages": [
    {"stage": "product-definition", "reason": "..."},
    {"stage": "deployment", "reason": "..."}
  ]
}
```

### Unknown Profile

```bash
tms profile enterprise
```

```
Error: unknown artifact-availability profile "enterprise" (want first-party, third-party, or open-source)
```

Exits `1`.

## See Also

- [analyze](analyze.md) — where a profile governs which stages plan mode will open a run for
- [Artifact Availability Profiles](../specification/artifact-availability.md) — the full first-party/third-party/open-source reference
