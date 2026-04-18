# JSON Schema

Threat Model Spec provides JSON Schema files for validating threat model documents. The schemas are generated from Go types using the `invopop/jsonschema` library.

## Schema Files

| Schema | Description | Location |
|--------|-------------|----------|
| `threat-model.schema.json` | ThreatModel format (multi-diagram) | `schema/threat-model.schema.json` |
| `diagram.schema.json` | DiagramIR format (single diagram) | `schema/diagram.schema.json` |

## Using the Schemas

### Programmatic Access (Go)

The schemas are embedded in the `schema` package:

```go
import "github.com/grokify/threat-model-spec/schema"

// Access embedded schemas
threatModelSchema := schema.ThreatModelSchema
diagramSchema := schema.DiagramSchema
```

### Validation with External Tools

You can validate JSON files against the schemas using tools like `ajv`:

```bash
# Install ajv-cli
npm install -g ajv-cli

# Validate a ThreatModel
ajv validate -s schema/threat-model.schema.json -d threat-model.json

# Validate a DiagramIR
ajv validate -s schema/diagram.schema.json -d attack.json
```

### IDE Integration

Configure your IDE to use the schemas for autocomplete and validation:

**VS Code** (`.vscode/settings.json`):

```json
{
  "json.schemas": [
    {
      "fileMatch": ["**/threat-model.json", "**/threatmodel.json"],
      "url": "./schema/threat-model.schema.json"
    },
    {
      "fileMatch": ["**/*_chain.json", "**/*_sequence.json", "**/dfd.json"],
      "url": "./schema/diagram.schema.json"
    }
  ]
}
```

## Regenerating Schemas

If you modify the Go types, regenerate the schemas:

```bash
# Build the generator
go build -o genschema ./cmd/genschema

# Generate schemas
./genschema schema/

# Validate with schemago
schemago lint schema/threat-model.schema.json
schemago lint schema/diagram.schema.json
```

## Schema Validation (schemago)

The schemas are validated using `schemago lint` to ensure Go compatibility:

- No ambiguous union types (`anyOf`/`oneOf`)
- Consistent discriminator fields
- Clean mapping to Go types

## Schema Structure

### ThreatModel Schema

```
ThreatModel
├── id (string, required)
├── title (string, required)
├── description (string)
├── version (string)
├── authors (array of Author)
├── references (array of Reference)
├── mappings (Mappings)
└── diagrams (array of DiagramView, required)
    └── DiagramView
        ├── type (enum: dfd, attack-chain, sequence)
        ├── title (string)
        ├── mappings (Mappings, overrides parent)
        └── ... diagram-specific fields
```

### DiagramIR Schema

```
DiagramIR
├── type (enum: dfd, attack-chain, sequence, required)
├── title (string, required)
├── description (string)
├── direction (enum: right, down, left, up)
├── legend (Legend)
├── mappings (Mappings)
├── elements (array of Element)
├── boundaries (array of Boundary)
├── flows (array of Flow)
├── attacks (array of Attack)
├── targets (array of Target)
├── actors (array of Actor)
├── phases (array of Phase)
└── messages (array of Message)
```

## Next Steps

- [JSON IR Overview](index.md) — Format documentation
- [Element Types](elements.md) — Element schema details
- [Framework Mappings](mappings.md) — Mappings schema details
