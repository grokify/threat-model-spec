package ir

// TimelineEvent is a single dated entry in a threat model's incident timeline.
// It captures the chronology of an attack chain — when things happened and,
// optionally, which phase of the campaign each event belongs to.
type TimelineEvent struct {
	// Date is when the event occurred. It may be a plain date ("2026-07-11"),
	// a date range ("2026-07-04 to 07-06"), or a timestamp with a time zone
	// ("2026-07-11 16:07 UTC").
	Date string `json:"date"`

	// Event is a human-readable description of what happened.
	Event string `json:"event"`

	// Phase is an optional grouping label (e.g. "initial access",
	// "escalation", "exfiltration") used to cluster related events.
	Phase string `json:"phase,omitempty"`
}
