package ostrace

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// FilterConfig represents the root configuration for filters
type FilterConfig struct {
	Filters []Filter `yaml:"filters"`
}

// Filter represents a single filter or logical operation
type Filter struct {
	Type     string   `yaml:"type,omitempty"`     // "AND", "OR", "NOT" (for logical operations)
	Field    string   `yaml:"field,omitempty"`    // "message", "pid", "subsystem", "category", "level", "filename", "image_name"
	Operator string   `yaml:"operator,omitempty"` // "CONTAINS", "EQUALS", "NOT_CONTAINS", "STARTS_WITH", "ENDS_WITH", "REGEX"
	Value    string   `yaml:"value,omitempty"`    // Pattern/value to match
	Children []Filter `yaml:"children,omitempty"` // For nested filters (AND/OR/NOT)

	// Pre-compiled regex for performance (not serialized)
	// Eliminates 10-100x overhead from compiling regex on every log entry
	compiledRegex *regexp.Regexp `yaml:"-"`
}

// LoadFilterConfig loads a filter configuration from a YAML file
func LoadFilterConfig(path string) (*FilterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter config file: %w", err)
	}

	var config FilterConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML filter config: %w", err)
	}

	// Validate the configuration
	for _, filter := range config.Filters {
		if err := validateFilter(filter); err != nil {
			return nil, fmt.Errorf("invalid filter configuration: %w", err)
		}
	}

	// Pre-compile all regex filters for performance
	// This eliminates regex compilation overhead in the hot path
	for i := range config.Filters {
		if err := precompileFilter(&config.Filters[i]); err != nil {
			return nil, fmt.Errorf("failed to compile regex: %w", err)
		}
	}

	return &config, nil
}

// precompileFilter recursively compiles all REGEX filters for performance
// This is critical for high-throughput scenarios (10K+ logs/sec)
func precompileFilter(filter *Filter) error {
	if filter.Operator == "REGEX" && filter.Value != "" {
		compiled, err := regexp.Compile(filter.Value)
		if err != nil {
			return fmt.Errorf("invalid regex '%s': %w", filter.Value, err)
		}
		filter.compiledRegex = compiled
	}

	// Recursively compile children
	for i := range filter.Children {
		if err := precompileFilter(&filter.Children[i]); err != nil {
			return err
		}
	}

	return nil
}

// validateFilter checks if a filter is valid
func validateFilter(filter Filter) error {
	// Check logical operators
	if filter.Type != "" {
		switch filter.Type {
		case "AND", "OR", "NOT":
			if len(filter.Children) == 0 {
				return fmt.Errorf("%s filter must have children", filter.Type)
			}
			// Recursively validate children
			for _, child := range filter.Children {
				if err := validateFilter(child); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("unknown filter type: %s", filter.Type)
		}
	}

	// Check field-based filters
	if filter.Field == "" {
		return fmt.Errorf("filter must have either 'type' or 'field' specified")
	}

	// Validate field names
	switch filter.Field {
	case "message", "pid", "level", "image_name", "filename", "category", "subsystem":
		// Valid fields
	default:
		return fmt.Errorf("unknown field: %s", filter.Field)
	}

	// Validate operators
	switch filter.Operator {
	case "CONTAINS", "EQUALS", "NOT_CONTAINS", "STARTS_WITH", "ENDS_WITH", "REGEX":
		// Valid operators
	default:
		return fmt.Errorf("unknown operator: %s", filter.Operator)
	}

	// For REGEX operator, validate the regex pattern
	if filter.Operator == "REGEX" {
		if _, err := regexp.Compile(filter.Value); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	return nil
}

// EvaluateFilters checks if a log entry matches any of the filters
func EvaluateFilters(entry *LogEntry, config *FilterConfig) bool {
	if config == nil || len(config.Filters) == 0 {
		return true // No filters means accept all
	}

	// If any filter matches, accept the entry
	for _, filter := range config.Filters {
		if EvaluateFilter(entry, filter) {
			return true
		}
	}

	return false
}

// EvaluateFilter evaluates a single filter against a log entry
func EvaluateFilter(entry *LogEntry, filter Filter) bool {
	switch filter.Type {
	case "AND":
		// All children must match
		for _, child := range filter.Children {
			if !EvaluateFilter(entry, child) {
				return false
			}
		}
		return true

	case "OR":
		// At least one child must match
		for _, child := range filter.Children {
			if EvaluateFilter(entry, child) {
				return true
			}
		}
		return false

	case "NOT":
		// Negate the first child
		if len(filter.Children) > 0 {
			return !EvaluateFilter(entry, filter.Children[0])
		}
		return false

	default:
		// Field-based filter
		return evaluateFieldFilter(entry, filter)
	}
}

// evaluateFieldFilter evaluates a field-based filter
func evaluateFieldFilter(entry *LogEntry, filter Filter) bool {
	var fieldValue string

	// Extract the field value from the log entry
	switch filter.Field {
	case "message":
		fieldValue = entry.Message
	case "pid":
		fieldValue = strconv.Itoa(entry.ProcessID)
	case "level":
		fieldValue = entry.Level
	case "image_name":
		fieldValue = entry.ImageName
	case "filename":
		fieldValue = entry.Filename
	case "category":
		fieldValue = entry.Category
	case "subsystem":
		fieldValue = entry.Subsystem
	default:
		return false // Unknown field
	}

	// Apply the operator
	switch filter.Operator {
	case "EQUALS":
		return fieldValue == filter.Value

	case "CONTAINS":
		return strings.Contains(fieldValue, filter.Value)

	case "NOT_CONTAINS":
		return !strings.Contains(fieldValue, filter.Value)

	case "STARTS_WITH":
		return strings.HasPrefix(fieldValue, filter.Value)

	case "ENDS_WITH":
		return strings.HasSuffix(fieldValue, filter.Value)

	case "REGEX":
		// Use pre-compiled regex for 10-100x better performance
		if filter.compiledRegex != nil {
			return filter.compiledRegex.MatchString(fieldValue)
		}
		// Fallback if not pre-compiled (shouldn't happen with LoadFilterConfig)
		matched, err := regexp.MatchString(filter.Value, fieldValue)
		if err != nil {
			return false // Invalid regex
		}
		return matched

	default:
		return false // Unknown operator
	}
}

// CreateSimpleFilter creates a simple "message contains" filter
func CreateSimpleFilter(pattern string) *FilterConfig {
	return &FilterConfig{
		Filters: []Filter{
			{
				Field:    "message",
				Operator: "CONTAINS",
				Value:    pattern,
			},
		},
	}
}
