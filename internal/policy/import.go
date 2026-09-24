package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/qredin/qredin/pkg/spiffeid"
	"gopkg.in/yaml.v3"
)

var (
	ErrYAMLImportFailed    = errors.New("policy: YAML import failed")
	ErrInvalidPolicyFormat = errors.New("policy: invalid policy format")
)

// YAMLPolicy represents a policy in YAML format for import.
type YAMLPolicy struct {
	ID          string          `yaml:"id" json:"id"`
	Version     int64           `yaml:"version" json:"version"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Scope       YAMLPolicyScope `yaml:"scope" json:"scope"`
	Rules       []YAMLRule      `yaml:"rules" json:"rules"`
	Status      string          `yaml:"status" json:"status"`
	Approvers   []string        `yaml:"approvers,omitempty" json:"approvers,omitempty"`
}

// YAMLPolicyScope represents policy scope in YAML format.
type YAMLPolicyScope struct {
	TenantID        string `yaml:"tenant_id" json:"tenant_id"`
	EnvironmentID   string `yaml:"environment_id" json:"environment_id"`
	TrustDomain     string `yaml:"trust_domain" json:"trust_domain"`
	SubjectSPIFFEID string `yaml:"subject_spiffe_id,omitempty" json:"subject_spiffe_id,omitempty"`
}

// YAMLRule represents a policy rule in YAML format.
type YAMLRule struct {
	ID          string                 `yaml:"id" json:"id"`
	Effect      string                 `yaml:"effect" json:"effect"`
	Actions     []string               `yaml:"actions" json:"actions"`
	Resources   []string               `yaml:"resources" json:"resources"`
	Conditions  map[string]interface{} `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Explanation string                 `yaml:"explanation,omitempty" json:"explanation,omitempty"`
}

// FromYAML imports a policy from YAML bytes.
func FromYAML(data []byte) (Policy, error) {
	var yamlPolicy YAMLPolicy
	if err := yaml.Unmarshal(data, &yamlPolicy); err != nil {
		return Policy{}, fmt.Errorf("%w: failed to unmarshal YAML: %v", ErrYAMLImportFailed, err)
	}

	policy, err := yamlPolicy.ToPolicy()
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrYAMLImportFailed, err)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("%w: invalid imported policy: %v", ErrInvalidPolicyFormat, err)
	}

	return policy, nil
}

// FromYAMLFile imports a policy from a YAML file.
func FromYAMLFile(filePath string) (Policy, error) {
	if !strings.HasSuffix(filePath, ".yaml") && !strings.HasSuffix(filePath, ".yml") {
		return Policy{}, fmt.Errorf("%w: file must have .yaml or .yml extension: %s", ErrYAMLImportFailed, filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: failed to read YAML file: %v", ErrYAMLImportFailed, err)
	}

	return FromYAML(data)
}

// ToPolicy converts a YAMLPolicy to a Policy.
func (yp YAMLPolicy) ToPolicy() (Policy, error) {
	td, err := spiffeid.TrustDomainFromString(yp.Scope.TrustDomain)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: invalid trust domain: %v", ErrInvalidPolicy, err)
	}
	tp := Policy{
		ID:      yp.ID,
		Version: yp.Version,
		Scope: PolicyScope{
			TenantID:        yp.Scope.TenantID,
			EnvironmentID:   yp.Scope.EnvironmentID,
			TrustDomain:     td,
			SubjectSPIFFEID: yp.Scope.SubjectSPIFFEID,
		},
		Description: yp.Description,
		Rules:       make([]Rule, 0, len(yp.Rules)),
		Status:      PolicyStatusDraft,
		Approvers:   yp.Approvers,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	for _, yr := range yp.Rules {
		rule := Rule{
			ID:          yr.ID,
			Effect:      Effect(yr.Effect),
			Actions:     yr.Actions,
			Resources:   yr.Resources,
			Conditions:  yr.Conditions,
			Explanation: yr.Explanation,
		}
		tp.Rules = append(tp.Rules, rule)
	}

	if yp.Status != "" {
		if status := PolicyStatus(yp.Status); status.IsValid() {
			tp.Status = status
		}
	}

	return tp, nil
}

// PolicyStatus.IsValid checks if the status is valid.
func (s PolicyStatus) IsValid() bool {
	return s == PolicyStatusDraft || s == PolicyStatusPending || s == PolicyStatusActive ||
		s == PolicyStatusSuspended || s == PolicyStatusRevoked
}
