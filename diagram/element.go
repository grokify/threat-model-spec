// Package diagram provides types for building threat model diagrams
// that can be rendered to D2 format.
package diagram

// ElementType represents the type of a DFD element.
type ElementType string

const (
	// Process represents a process that transforms data.
	Process ElementType = "process"

	// DataStore represents persistent data storage.
	DataStore ElementType = "datastore"

	// ExternalEntity represents an actor outside the system boundary.
	ExternalEntity ElementType = "external-entity"

	// ExternalSystem represents an external system.
	ExternalSystem ElementType = "external-system"

	// Browser represents a web browser.
	Browser ElementType = "browser"

	// WebServer represents a web server.
	WebServer ElementType = "web-server"

	// APIEndpoint represents an API endpoint.
	APIEndpoint ElementType = "api-endpoint"

	// Database represents a database.
	Database ElementType = "database"

	// AIAgent represents an AI agent.
	AIAgent ElementType = "ai-agent"

	// Gateway represents a gateway or proxy.
	Gateway ElementType = "gateway"

	// ConfigStore represents a configuration store.
	ConfigStore ElementType = "config-store"
)

// D2Shape returns the D2 shape for this element type.
func (e ElementType) D2Shape() string {
	switch e {
	case DataStore, Database, ConfigStore:
		return "cylinder"
	case ExternalEntity:
		return "person"
	case Gateway:
		return "hexagon"
	default:
		return "rectangle"
	}
}

// D2Class returns the D2 style class for this element type.
func (e ElementType) D2Class() string {
	return string(e)
}

// Element represents a component in the threat model diagram.
type Element struct {
	// ID is the unique identifier for this element.
	ID string `json:"id"`

	// Label is the display text for this element.
	Label string `json:"label"`

	// Type is the element type.
	Type ElementType `json:"type"`

	// ParentID is the ID of the parent boundary (if nested).
	ParentID string `json:"parentId,omitempty"`

	// Style overrides the default style.
	Style *Style `json:"style,omitempty"`

	// Compromised indicates if this element has been compromised.
	Compromised bool `json:"compromised,omitempty"`

	// Description provides additional context.
	Description string `json:"description,omitempty"`
}

// FullID returns the full D2 path including parent.
func (e Element) FullID() string {
	if e.ParentID != "" {
		return e.ParentID + "." + e.ID
	}
	return e.ID
}

// Style represents visual styling for diagram elements.
type Style struct {
	Fill         string  `json:"fill,omitempty"`
	Stroke       string  `json:"stroke,omitempty"`
	StrokeWidth  int     `json:"strokeWidth,omitempty"`
	StrokeDash   int     `json:"strokeDash,omitempty"`
	FontSize     int     `json:"fontSize,omitempty"`
	FontColor    string  `json:"fontColor,omitempty"`
	BorderRadius int     `json:"borderRadius,omitempty"`
	Opacity      float64 `json:"opacity,omitempty"`
}

// Merge combines this style with another, with other taking precedence.
func (s *Style) Merge(other *Style) *Style {
	if s == nil {
		return other
	}
	if other == nil {
		return s
	}

	result := *s
	if other.Fill != "" {
		result.Fill = other.Fill
	}
	if other.Stroke != "" {
		result.Stroke = other.Stroke
	}
	if other.StrokeWidth != 0 {
		result.StrokeWidth = other.StrokeWidth
	}
	if other.StrokeDash != 0 {
		result.StrokeDash = other.StrokeDash
	}
	if other.FontSize != 0 {
		result.FontSize = other.FontSize
	}
	if other.FontColor != "" {
		result.FontColor = other.FontColor
	}
	if other.BorderRadius != 0 {
		result.BorderRadius = other.BorderRadius
	}
	if other.Opacity != 0 {
		result.Opacity = other.Opacity
	}
	return &result
}
