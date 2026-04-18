---
name: numbered-flow-creation
description: Guidelines for creating numbered data flow sequences in threat model diagrams
triggers: [numbered, flow, sequence, steps, attack chain]
dependencies: [d2]
---

# Numbered Flow Creation

Guidelines for creating clear, sequential numbered flows in threat model diagrams.

## When to Use Numbered Flows

- **Data Flow Diagrams**: Show the sequence of normal operations
- **Attack Chains**: Show step-by-step attack progression
- **Dual Diagrams**: Separate normal (letters/numbers) from attack (numbers with red)

## Numbering Conventions

### Single Flow Type

Use simple numbers:

```d2
user -> app: "1. Login request"
app -> db: "2. Query credentials"
db -> app: "3. Return result"
app -> user: "4. Session token"
```

### Multiple Flow Types

Use letters for one flow, numbers for another:

**Normal Operation (letters A-Z)**:
```d2
user -> browser: "A. Open application" { style.stroke: "#1565c0" }
browser -> server: "B. API request" { style.stroke: "#1565c0" }
```

**Alternative Flow (numbers 1-N)**:
```d2
user -> ide: "1. Write code" { style.stroke: "#2e7d32" }
ide -> agent: "2. Request assistance" { style.stroke: "#2e7d32" }
```

### Attack Flows

Always use numbers with red color:

```d2
attacker -> victim: "1. Phishing email" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}

victim -> malicious-site: "2. Click link" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}
```

## Label Format

### Standard Format

```
{number}. {action verb} {object}
```

Examples:
- "1. Send request"
- "2. Validate token"
- "3. Query database"
- "4. Return results"

### With Framework Annotations

```
{number}. {action} ({framework code})
```

Examples:
- "1. Visit page (TA0001)"
- "2. Brute-force auth (TA0006)"
- "3. Steal credentials (T1552)"

## Color Coding

| Flow Type | Stroke Color | Width | Use |
|-----------|--------------|-------|-----|
| Normal (primary) | #2e7d32 (green) | 2 | Main happy path |
| Normal (secondary) | #1565c0 (blue) | 2 | Alternative path |
| Attack | #c62828 (red) | 3 | Malicious activity |
| Response | same as request | 2 | Return data |

## Bidirectional Flows

For request/response pairs, use separate edges:

```d2
client -> server: "1. Request" { style.stroke: "#2e7d32" }
server -> client: "2. Response" { style.stroke: "#2e7d32" }
```

Not:
```d2
# Avoid - less clear
client <-> server: "Request/Response"
```

## Self-Loops

For operations that loop on a single element:

```d2
gateway -> gateway: "3. Brute-force password" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}
```

## Grouping Related Steps

Use sub-ranges for related operations:

```d2
# Steps 6-8: Data collection
agent -> api-keys: "6. Read API keys"
gateway -> config: "7. Read config"
gateway -> logs: "8. Read logs"
```

## Validation Rules

1. **Sequential**: Numbers should not skip (1, 2, 3... not 1, 3, 5)
2. **Starting Point**: Start at 1 or A
3. **Consistent Style**: Same flow type uses same color
4. **Descriptive**: Each label describes the action
5. **Unique**: No duplicate numbers in same diagram

## Anti-Patterns

### ❌ Inconsistent Numbering
```d2
user -> app: "1. Login"
app -> db: "3. Query"  # Skipped 2!
```

### ❌ Missing Numbers
```d2
user -> app: "Login"  # No number
app -> db: "2. Query"
```

### ❌ Mixed Colors for Same Flow
```d2
user -> app: "1. Login" { style.stroke: "#2e7d32" }
app -> db: "2. Query" { style.stroke: "#1565c0" }  # Different color!
```

## Template

```d2
# Normal flow (green)
source -> target: "{N}. {Action}" {
  style.stroke: "#2e7d32"
  style.stroke-width: 2
}

# Attack flow (red)
source -> target: "{N}. {Action}" {
  style.stroke: "#c62828"
  style.stroke-width: 3
}
```
