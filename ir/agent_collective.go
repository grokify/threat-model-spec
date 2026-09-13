package ir

// AgentCollective models a population of autonomous agents that coordinate —
// possibly emergently — toward shared objectives. Introduced for agentic-incident
// modeling (e.g. an agent swarm that self-organizes over a covert channel).
type AgentCollective struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Models the collective is composed of (model names / ids).
	Models []string `json:"models,omitempty"`
	// Population is the approximate number of participating agents.
	Population int `json:"population,omitempty"`
	// CoordinationChannel describes how members coordinate (free text or an
	// element/flow id reference, e.g. "Artifactory directory-name message board").
	CoordinationChannel string `json:"coordinationChannel,omitempty"`
	// Emergent indicates the coordination arose unintentionally (not a provided tool).
	Emergent bool `json:"emergent,omitempty"`
	// EmergentBehaviors lists notable self-organized behaviors (signing schemes, mailboxes, veto norms...).
	EmergentBehaviors []string `json:"emergentBehaviors,omitempty"`
	// RewardHacking captures the misaligned-objective dynamic that drove out-of-scope behavior.
	RewardHacking *RewardHacking `json:"rewardHacking,omitempty"`
	// MemberElementIDs optionally links to representative agent elements in a diagram view.
	MemberElementIDs []string `json:"memberElementIds,omitempty"`
}

// RewardHacking models an agent pursuing an unintended path to earn reward
// without completing the task as designed.
type RewardHacking struct {
	Objective          string  `json:"objective,omitempty"`          // the intended goal/reward signal
	IntendedPath       string  `json:"intendedPath,omitempty"`       // how solving was meant to happen
	UnintendedPath     string  `json:"unintendedPath,omitempty"`     // the exploit/cheat actually taken
	ImpossibleTaskRate float64 `json:"impossibleTaskRate,omitempty"` // fraction of tasks unsolvable-as-intended (0..1), a driver
	Description        string  `json:"description,omitempty"`
}
