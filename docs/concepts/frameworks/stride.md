# STRIDE

STRIDE is a threat modeling framework developed by Microsoft that categorizes threats into six categories.

## Categories

| Code | Category | Description | Color |
|------|----------|-------------|-------|
| **S** | Spoofing | Illegally accessing another user's credentials | Red |
| **T** | Tampering | Malicious modification of data | Yellow |
| **R** | Repudiation | Denying actions without proof | Purple |
| **I** | Information Disclosure | Exposing data to unauthorized parties | Blue |
| **D** | Denial of Service | Making systems unavailable | Orange |
| **E** | Elevation of Privilege | Gaining unauthorized access levels | Green |

## Detailed Descriptions

### Spoofing (S)

Spoofing refers to illegally accessing and using another user's authentication information, such as username and password.

**Examples:**

- Credential theft via phishing
- Session hijacking
- Man-in-the-middle attacks
- Forged authentication tokens

**Mitigations:**

- Strong authentication (MFA)
- Certificate pinning
- Secure session management

### Tampering (T)

Tampering involves malicious modification of data, such as unauthorized changes to persistent data or data in transit.

**Examples:**

- Modifying database records
- Altering configuration files
- Man-in-the-middle data modification
- Malicious code injection

**Mitigations:**

- Digital signatures
- Integrity checks (checksums, hashes)
- Access control lists
- Audit logging

### Repudiation (R)

Repudiation refers to users denying performing an action without other parties having any way to prove otherwise.

**Examples:**

- Denying a transaction occurred
- Claiming account was compromised
- Disputing access to sensitive data

**Mitigations:**

- Comprehensive audit logging
- Digital signatures
- Timestamps
- Non-repudiation protocols

### Information Disclosure (I)

Information Disclosure involves exposing information to individuals who are not supposed to have access to it.

**Examples:**

- Data breaches
- Verbose error messages
- Directory traversal
- Side-channel attacks

**Mitigations:**

- Encryption (at rest and in transit)
- Access controls
- Data classification
- Secure error handling

### Denial of Service (D)

Denial of Service refers to attacks that deny service to valid users, making a system unavailable or unusable.

**Examples:**

- DDoS attacks
- Resource exhaustion
- Application crashes
- Infinite loops

**Mitigations:**

- Rate limiting
- Resource quotas
- Load balancing
- Input validation

### Elevation of Privilege (E)

Elevation of Privilege occurs when an unprivileged user gains privileged access, compromising the entire system.

**Examples:**

- SQL injection leading to admin access
- Buffer overflow exploits
- Privilege escalation vulnerabilities
- Insecure direct object references

**Mitigations:**

- Principle of least privilege
- Input validation
- Sandboxing
- Regular security updates

## JSON Mapping Format

```json
{
  "mappings": {
    "stride": [
      {
        "category": "S",
        "name": "Spoofing",
        "description": "Attacker impersonates legitimate localhost client"
      },
      {
        "category": "I",
        "name": "Information Disclosure",
        "description": "API keys and credentials exposed"
      }
    ]
  }
}
```

## D2 Style Classes

STRIDE threats have dedicated D2 style classes for visual annotation:

| Category | Badge Class | Box Class |
|----------|-------------|-----------|
| Spoofing | `threat-spoofing` | `threat-box-spoofing` |
| Tampering | `threat-tampering` | `threat-box-tampering` |
| Repudiation | `threat-repudiation` | `threat-box-repudiation` |
| Info Disclosure | `threat-info-disclosure` | `threat-box-info-disclosure` |
| DoS | `threat-dos` | `threat-box-dos` |
| Elevation | `threat-elevation` | `threat-box-elevation` |

See [STRIDE Styles](../../styles/stride.md) for usage examples.

## Go Package

```go
import "github.com/grokify/threat-model-spec/stride"

// Get all threat types
for _, t := range stride.AllThreatTypes() {
    fmt.Printf("%s: %s (color: %s)\n", t.Code(), t.String(), t.Color())
}

// Create a threat
threat := stride.Threat{
    Type:        stride.Spoofing,
    Title:       "Credential Theft",
    Description: "Attacker steals user credentials via phishing",
    Severity:    "High",
}
```

## References

- [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
