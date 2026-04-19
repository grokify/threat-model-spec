# LINDDUN Privacy Framework

LINDDUN is a privacy threat modeling framework developed at KU Leuven. It complements STRIDE by focusing on privacy-specific threats rather than security threats.

## Categories

| Category | Name | Description |
|----------|------|-------------|
| **L** | Linkability | Ability to link items of interest (records, users, actions) |
| **I** | Identifiability | Ability to identify a data subject |
| **N** | Non-repudiation | Inability to deny an action (privacy concern when deniability is needed) |
| **D** | Detectability | Ability to detect existence of an item of interest |
| **Di** | Disclosure of Information | Exposure of personal information |
| **U** | Unawareness | Lack of awareness about data collection/processing |
| **Nc** | Non-compliance | Failure to comply with privacy regulations |

## Usage in Threat Model Spec

### Mappings

Add LINDDUN mappings to your threat model:

```json
{
  "mappings": {
    "linddun": [
      {
        "category": "I",
        "name": "Identifiability",
        "description": "User can be identified through session tokens"
      },
      {
        "category": "Di",
        "name": "Disclosure",
        "description": "Personal data exposed in API response"
      }
    ]
  }
}
```

### D2 Legend

Enable the LINDDUN legend in your diagrams:

```json
{
  "legend": {
    "showLINDDUN": true
  }
}
```

This renders a color-coded legend with all LINDDUN categories.

## LINDDUN vs STRIDE

| Aspect | STRIDE | LINDDUN |
|--------|--------|---------|
| Focus | Security threats | Privacy threats |
| Origin | Microsoft | KU Leuven |
| Categories | 6 | 7 |
| Use case | System security | Data protection |

## When to Use

- **GDPR compliance** — Map privacy risks to regulatory requirements
- **Privacy by Design** — Identify privacy threats early in development
- **Data protection** — Analyze how personal data is handled
- **Combined with STRIDE** — Comprehensive security + privacy threat modeling

## D2 Styling

LINDDUN threats are rendered with distinct colors:

| Category | Fill Color | Stroke Color |
|----------|------------|--------------|
| L - Linkability | `#e8eaf6` | `#3f51b5` (Indigo) |
| I - Identifiability | `#e3f2fd` | `#1976d2` (Blue) |
| N - Non-repudiation | `#fff3e0` | `#f57c00` (Orange) |
| D - Detectability | `#fce4ec` | `#c2185b` (Pink) |
| Di - Disclosure | `#ffebee` | `#c62828` (Red) |
| U - Unawareness | `#f3e5f5` | `#7b1fa2` (Purple) |
| Nc - Non-compliance | `#efebe9` | `#5d4037` (Brown) |

## References

- [LINDDUN Official Website](https://linddun.org/)
- [LINDDUN GO (Lightweight Version)](https://linddun.org/linddun-go/)
- [Privacy Threat Modeling](https://www.linddun.org/linddun)
