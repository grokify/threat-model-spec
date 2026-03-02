package diagram

// BoundaryType represents the type of trust boundary.
type BoundaryType string

const (
	// TrustBoundary is a generic trust boundary.
	TrustBoundary BoundaryType = "trust-boundary"

	// ExternalBoundary represents an untrusted zone (internet, external users).
	ExternalBoundary BoundaryType = "trust-boundary-external"

	// InternalBoundary represents a trusted zone (internal network).
	InternalBoundary BoundaryType = "trust-boundary-internal"

	// DMZBoundary represents a semi-trusted zone.
	DMZBoundary BoundaryType = "trust-boundary-dmz"

	// BrowserBoundary represents a browser sandbox.
	BrowserBoundary BoundaryType = "trust-boundary-browser"

	// LocalhostBoundary represents localhost (often implicitly trusted).
	LocalhostBoundary BoundaryType = "trust-boundary-localhost"

	// BreachedBoundary represents a boundary that has been compromised.
	BreachedBoundary BoundaryType = "trust-boundary-breached"

	// WeakBoundary represents a boundary with weak security.
	WeakBoundary BoundaryType = "trust-boundary-weak"
)

// D2Class returns the D2 style class for this boundary type.
func (b BoundaryType) D2Class() string {
	return string(b)
}

// Boundary represents a trust boundary in the diagram.
type Boundary struct {
	// ID is the unique identifier for this boundary.
	ID string `json:"id"`

	// Label is the display text for this boundary.
	Label string `json:"label"`

	// Type is the boundary type.
	Type BoundaryType `json:"type"`

	// ParentID is the ID of the parent boundary (for nested boundaries).
	ParentID string `json:"parentId,omitempty"`

	// Style overrides the default style.
	Style *Style `json:"style,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`

	// Breached indicates if this boundary has been breached.
	Breached bool `json:"breached,omitempty"`
}

// FullID returns the full D2 path including parent.
func (b Boundary) FullID() string {
	if b.ParentID != "" {
		return b.ParentID + "." + b.ID
	}
	return b.ID
}

// GetEffectiveType returns the actual type, considering breach status.
func (b Boundary) GetEffectiveType() BoundaryType {
	if b.Breached {
		return BreachedBoundary
	}
	return b.Type
}
