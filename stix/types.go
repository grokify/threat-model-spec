package stix

// Bundle is a STIX 2.1 Bundle object that contains a collection of STIX objects.
type Bundle struct {
	Type    string   `json:"type"`
	ID      string   `json:"id"`
	Objects []Object `json:"objects"`
}

// NewBundle creates a new STIX Bundle.
func NewBundle() *Bundle {
	return &Bundle{
		Type:    "bundle",
		ID:      "bundle--" + generateUUID(),
		Objects: make([]Object, 0),
	}
}

// AddObject adds a STIX object to the bundle.
func (b *Bundle) AddObject(obj Object) {
	if obj != nil {
		b.Objects = append(b.Objects, obj)
	}
}

// Object is an interface for all STIX objects.
type Object interface {
	GetType() string
	GetID() string
}

// ExternalReference represents an external reference to another source.
type ExternalReference struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id,omitempty"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// Identity represents a STIX Identity object.
type Identity struct {
	Type          string `json:"type"`
	SpecVersion   string `json:"spec_version"`
	ID            string `json:"id"`
	Created       string `json:"created"`
	Modified      string `json:"modified"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	IdentityClass string `json:"identity_class"`
}

func (i *Identity) GetType() string { return i.Type }
func (i *Identity) GetID() string   { return i.ID }

// ThreatActor represents a STIX Threat Actor object.
type ThreatActor struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	ThreatActorTypes   []string            `json:"threat_actor_types"`
	Aliases            []string            `json:"aliases,omitempty"`
	Roles              []string            `json:"roles,omitempty"`
	Goals              []string            `json:"goals,omitempty"`
	Sophistication     string              `json:"sophistication,omitempty"`
	ResourceLevel      string              `json:"resource_level,omitempty"`
	PrimaryMotivation  string              `json:"primary_motivation,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

func (t *ThreatActor) GetType() string { return t.Type }
func (t *ThreatActor) GetID() string   { return t.ID }

// AttackPattern represents a STIX Attack Pattern object.
type AttackPattern struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	Aliases            []string            `json:"aliases,omitempty"`
	KillChainPhases    []KillChainPhase    `json:"kill_chain_phases,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

func (a *AttackPattern) GetType() string { return a.Type }
func (a *AttackPattern) GetID() string   { return a.ID }

// KillChainPhase represents a phase in a kill chain.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// Infrastructure represents a STIX Infrastructure object.
type Infrastructure struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	InfraType          string              `json:"infrastructure_types,omitempty"`
	Aliases            []string            `json:"aliases,omitempty"`
	KillChainPhases    []KillChainPhase    `json:"kill_chain_phases,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

func (i *Infrastructure) GetType() string { return i.Type }
func (i *Infrastructure) GetID() string   { return i.ID }

// Indicator represents a STIX Indicator object.
type Indicator struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Name               string              `json:"name,omitempty"`
	Description        string              `json:"description,omitempty"`
	IndicatorTypes     []string            `json:"indicator_types,omitempty"`
	Pattern            string              `json:"pattern"`
	PatternType        string              `json:"pattern_type"`
	PatternVersion     string              `json:"pattern_version,omitempty"`
	ValidFrom          string              `json:"valid_from"`
	ValidUntil         string              `json:"valid_until,omitempty"`
	KillChainPhases    []KillChainPhase    `json:"kill_chain_phases,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

func (i *Indicator) GetType() string { return i.Type }
func (i *Indicator) GetID() string   { return i.ID }

// Vulnerability represents a STIX Vulnerability object.
type Vulnerability struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Name               string              `json:"name"`
	Description        string              `json:"description,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

func (v *Vulnerability) GetType() string { return v.Type }
func (v *Vulnerability) GetID() string   { return v.ID }

// Relationship represents a STIX Relationship object.
type Relationship struct {
	Type             string `json:"type"`
	SpecVersion      string `json:"spec_version"`
	ID               string `json:"id"`
	Created          string `json:"created"`
	Modified         string `json:"modified"`
	CreatedByRef     string `json:"created_by_ref,omitempty"`
	RelationshipType string `json:"relationship_type"`
	Description      string `json:"description,omitempty"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
	StartTime        string `json:"start_time,omitempty"`
	StopTime         string `json:"stop_time,omitempty"`
}

func (r *Relationship) GetType() string { return r.Type }
func (r *Relationship) GetID() string   { return r.ID }

// Note represents a STIX Note object for adding context.
type Note struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	CreatedByRef string   `json:"created_by_ref,omitempty"`
	Abstract     string   `json:"abstract,omitempty"`
	Content      string   `json:"content"`
	Authors      []string `json:"authors,omitempty"`
	ObjectRefs   []string `json:"object_refs"`
}

func (n *Note) GetType() string { return n.Type }
func (n *Note) GetID() string   { return n.ID }
