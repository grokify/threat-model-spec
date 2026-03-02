# Installation

Threat Model Spec can be used as a Go library or as a standalone CLI tool.

## Requirements

- Go 1.24 or later
- [D2](https://d2lang.com) v0.6+ (for SVG rendering)

## Go Library

Add the library to your Go project:

```bash
go get github.com/grokify/threat-model-spec
```

Import packages as needed:

```go
import (
    "github.com/grokify/threat-model-spec/ir"
    "github.com/grokify/threat-model-spec/diagram"
    "github.com/grokify/threat-model-spec/stix"
    "github.com/grokify/threat-model-spec/stride"
    "github.com/grokify/threat-model-spec/killchain"
)
```

## CLI Tool

Install the `tms` command-line tool:

```bash
go install github.com/grokify/threat-model-spec/cmd/tms@latest
```

Verify the installation:

```bash
tms version
# Output: tms version 0.1.0
```

## D2 Installation

The `--svg` flag requires the D2 CLI to be installed. See [d2lang.com](https://d2lang.com) for installation instructions.

=== "macOS (Homebrew)"

    ```bash
    brew install d2
    ```

=== "Linux"

    ```bash
    curl -fsSL https://d2lang.com/install.sh | sh -s --
    ```

=== "Windows"

    ```powershell
    winget install terrastruct.d2
    ```

=== "Go Install"

    ```bash
    go install oss.terrastruct.com/d2@latest
    ```

Verify D2 installation:

```bash
d2 --version
```

## Next Steps

- [Quick Start](quick-start.md) — Create your first threat model
- [Diagram Types](../concepts/diagram-types.md) — Learn about DFD, Attack Chain, and Sequence diagrams
- [CLI Reference](../cli/index.md) — Full command documentation
