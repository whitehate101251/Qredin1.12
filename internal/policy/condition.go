package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
)

// ConditionOperator is a constrained DSL operator.
type ConditionOperator string

const (
	OperatorAnd        ConditionOperator = "and"
	OperatorOr         ConditionOperator = "or"
	OperatorNot        ConditionOperator = "not"
	OperatorEq         ConditionOperator = "eq"
	OperatorIn         ConditionOperator = "in"
	OperatorPrefix     ConditionOperator = "prefix"
	OperatorGlob       ConditionOperator = "glob"
	OperatorCIDR       ConditionOperator = "cidr"
	OperatorTimeWindow ConditionOperator = "time_window"
	OperatorRiskBelow  ConditionOperator = "risk_below"
)

// ConditionNode is an immutable, typed condition tree node.
type ConditionNode struct {
	Operator ConditionOperator
	Value    interface{}
	Children []*ConditionNode
}

// Evaluate evaluates a condition against an authorization request and risk context.
func (n *ConditionNode) Evaluate(request AuthorizationRequest, context map[string]interface{}, risk map[string]RiskSignal) bool {
	if n == nil {
		return true
	}
	switch n.Operator {
	case OperatorAnd:
		for _, child := range n.Children {
			if child == nil || !child.Evaluate(request, context, risk) {
				return false
			}
		}
		return true
	case OperatorOr:
		for _, child := range n.Children {
			if child != nil && child.Evaluate(request, context, risk) {
				return true
			}
		}
		return false
	case OperatorNot:
		return n.Children != nil && len(n.Children) == 1 && n.Children[0] != nil && !n.Children[0].Evaluate(request, context, risk)
	case OperatorEq, OperatorIn, OperatorPrefix, OperatorGlob, OperatorCIDR, OperatorTimeWindow, OperatorRiskBelow:
		return n.evaluateLeaf(request, context, risk)
	default:
		return false
	}
}

func (n *ConditionNode) evaluateLeaf(request AuthorizationRequest, context map[string]interface{}, risk map[string]RiskSignal) bool {
	if n == nil || n.Value == nil {
		return false
	}
	expected, ok := n.Value.(map[string]interface{})
	if !ok {
		return false
	}
	value := request.ContextValue(fmt.Sprint(expected["field"]))
	switch n.Operator {
	case OperatorEq:
		return fmt.Sprint(value) == fmt.Sprint(expected["expected"])
	case OperatorIn:
		items, ok := expected["expected"].([]interface{})
		if !ok {
			return false
		}
		for _, item := range items {
			if fmt.Sprint(value) == fmt.Sprint(item) {
				return true
			}
		}
		return false
	case OperatorPrefix:
		return strings.HasPrefix(fmt.Sprint(value), fmt.Sprint(expected["expected"]))
	case OperatorGlob:
		return globMatch(fmt.Sprint(expected["expected"]), fmt.Sprint(value))
	case OperatorCIDR:
		return cidrMatch(fmt.Sprint(expected["expected"]), fmt.Sprint(value))
	case OperatorTimeWindow:
		window, ok := expected["window"].(map[string]interface{})
		if !ok {
			return false
		}
		now := request.Timestamp
		if raw, ok := context["time"]; ok {
			if t, err := parseTime(fmt.Sprint(raw)); err == nil {
				now = t
			}
		}
		start, err1 := parseTime(fmt.Sprint(window["start"]))
		end, err2 := parseTime(fmt.Sprint(window["end"]))
		if err1 != nil || err2 != nil {
			return false
		}
		return !now.Before(start) && !now.After(end)
	case OperatorRiskBelow:
		threshold, ok := expected["threshold"].(float64)
		if !ok {
			return false
		}
		signal, ok := risk[request.SubjectSPIFFEID]
		return ok && signal.Score < threshold
	default:
		return false
	}
}

// ConditionTrace records matched and unmatched leaves for explainability.
type ConditionTrace struct {
	Operator string            `json:"operator"`
	Value    interface{}       `json:"value,omitempty"`
	Matched  bool              `json:"matched"`
	Children []*ConditionTrace `json:"children,omitempty"`
}

// Trace builds a deterministic explainability tree for a condition node.
func (n *ConditionNode) Trace(request AuthorizationRequest, context map[string]interface{}, risk map[string]RiskSignal) *ConditionTrace {
	if n == nil {
		return nil
	}
	matched := n.Evaluate(request, context, risk)
	node := &ConditionTrace{Operator: string(n.Operator), Matched: matched}
	if n.Value != nil {
		node.Value = n.Value
	}
	if n.Children != nil {
		node.Children = make([]*ConditionTrace, 0, len(n.Children))
		for _, child := range n.Children {
			if child != nil {
				node.Children = append(node.Children, child.Trace(request, context, risk))
			}
		}
	}
	return node
}

// Condition builds a ConditionNode from the rule's Conditions map.
func (r *Rule) Condition() *ConditionNode {
	if r.Conditions == nil || len(r.Conditions) == 0 {
		return nil
	}
	conditions := make([]*ConditionNode, 0, len(r.Conditions))
	for key, value := range r.Conditions {
		conditions = append(conditions, &ConditionNode{Operator: ConditionOperator(key), Value: value})
	}
	return &ConditionNode{Operator: OperatorAnd, Children: conditions}
}

// EvaluateDSL evaluates the typed DSL condition against the request.
func (r Rule) EvaluateDSL(request AuthorizationRequest) bool {
	node := r.Condition()
	if node == nil {
		return true
	}
	risk := riskSignalsFromContext(request.Context)
	return node.Evaluate(request, request.Context, risk)
}

func riskSignalsFromContext(context map[string]interface{}) map[string]RiskSignal {
	out := make(map[string]RiskSignal)
	if raw, ok := context["risk"]; ok {
		if signals, ok := raw.([]RiskSignal); ok {
			for _, signal := range signals {
				out[signal.SubjectID] = signal
			}
		}
	}
	return out
}

func globMatch(pattern, value string) bool {
	if pattern == "" {
		return value == ""
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	if !strings.HasSuffix(value, parts[len(parts)-1]) {
		return false
	}
	remaining := value[len(parts[0]) : len(value)-len(parts[len(parts)-1])]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}
	return true
}

func cidrMatch(cidrPattern, value string) bool {
	_, ipnet, err := net.ParseCIDR(cidrPattern)
	if err != nil {
		return false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ipnet.Contains(ip)
}

// ContextValue returns a request context value, including request fields.
func (r AuthorizationRequest) ContextValue(key string) interface{} {
	switch key {
	case "action":
		return r.Action
	case "resource":
		return r.Resource
	case "method":
		return r.Method
	case "path":
		return r.Path
	case "audience":
		return r.Audience
	case "subject_spiffe_id", "identity", "spiffe_id":
		return r.SubjectSPIFFEID
	case "trust_domain":
		if id, err := spiffeid.FromString(r.SubjectSPIFFEID); err == nil {
			return id.TrustDomain().String()
		}
	case "tenant_id":
		if value, ok := r.Context["tenant_id"]; ok {
			return value
		}
	case "environment":
		if value, ok := r.Context["environment"]; ok {
			return value
		}
	}
	if value, ok := r.Context[key]; ok {
		return value
	}
	return nil
}

// MarshalJSON preserves the typed condition tree for persisted policies.
func (n *ConditionNode) MarshalJSON() ([]byte, error) {
	if n == nil {
		return []byte("null"), nil
	}
	if n.Children == nil || len(n.Children) == 0 {
		return json.Marshal(map[string]interface{}{string(n.Operator): n.Value})
	}
	children := make([]interface{}, 0, len(n.Children))
	for _, child := range n.Children {
		children = append(children, child)
	}
	return json.Marshal(map[string]interface{}{string(n.Operator): children})
}

// UnmarshalJSON restores a typed condition tree.
func (n *ConditionNode) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) != 1 {
		return fmt.Errorf("invalid condition")
	}
	for operator, value := range raw {
		n.Operator = ConditionOperator(operator)
		switch operator {
		case string(OperatorAnd), string(OperatorOr), string(OperatorNot):
			items, ok := value.([]interface{})
			if !ok {
				return fmt.Errorf("invalid condition children")
			}
			n.Children = make([]*ConditionNode, 0, len(items))
			for _, item := range items {
				data, _ := json.Marshal(item)
				var child ConditionNode
				if err := json.Unmarshal(data, &child); err != nil {
					return err
				}
				n.Children = append(n.Children, &child)
			}
		default:
			n.Value = value
		}
		return nil
	}
	return fmt.Errorf("invalid condition")
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q", value)
}
