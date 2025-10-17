# ostrace Filtering Guide

The `ostrace` command supports powerful client-side filtering capabilities to help you find specific log entries among the high volume of iOS system logs.

## Quick Start

### Simple Filtering

Use `--filter` for basic message content filtering:

```bash
# Filter logs containing "Microphone"
ios ostrace --filter "Microphone"

# With pymobiledevice3 tunnel
ios ostrace --pymobile-tunnel 49151 --filter "Bluetooth"
```

### Advanced Filtering with YAML

Use `--filter-config` for complex filtering logic:

```bash
# Use a filter configuration file
ios ostrace --filter-config filters.yaml
```

## Filter Configuration Format

Filter configurations use YAML format and support logical operations (AND, OR, NOT) and field-specific matching.

### Available Fields

- `message` - The log message content
- `process_id` - Numeric process ID
- `level` - Log level (info, debug, error, warning, etc.)
- `image_name` - Process/binary name (e.g., SpringBoard, bluetoothd)
- `filename` - Source file name
- `category` - Log category
- `subsystem` - Subsystem identifier (e.g., com.apple.bluetooth)

### Available Operators

- `EQUALS` - Exact match
- `CONTAINS` - Substring match (case-sensitive)
- `NOT_CONTAINS` - Does not contain substring
- `STARTS_WITH` - String starts with value
- `ENDS_WITH` - String ends with value
- `REGEX` - Regular expression match

## Examples

### Simple Field Filter

```yaml
# Match exact subsystem
filters:
  - field: subsystem
    operator: EQUALS
    value: com.apple.bluetooth
```

### Multiple Conditions (AND)

```yaml
# Bluetooth errors only
filters:
  - type: AND
    children:
      - field: subsystem
        operator: CONTAINS
        value: bluetooth
      - field: level
        operator: EQUALS
        value: error
```

### Multiple Options (OR)

```yaml
# Either errors or warnings
filters:
  - type: OR
    children:
      - field: level
        operator: EQUALS
        value: error
      - field: level
        operator: EQUALS
        value: warning
```

### Negation (NOT)

```yaml
# SpringBoard logs excluding gestures
filters:
  - type: AND
    children:
      - field: image_name
        operator: EQUALS
        value: SpringBoard
      - type: NOT
        children:
          - field: message
            operator: CONTAINS
            value: gesture
```

### Complex Nested Logic

```yaml
filters:
  # Match any of these conditions
  - type: OR
    children:
      # Bluetooth errors
      - type: AND
        children:
          - field: subsystem
            operator: CONTAINS
            value: bluetooth
          - field: level
            operator: EQUALS
            value: error
      
      # Memory pressure warnings
      - field: message
        operator: CONTAINS
        value: "memory pressure"
      
      # CoreData issues
      - type: AND
        children:
          - field: subsystem
            operator: STARTS_WITH
            value: com.apple.CoreData
          - type: OR
            children:
              - field: level
                operator: EQUALS
                value: error
              - field: level
                operator: EQUALS
                value: warning
```

### Regex Patterns

```yaml
# Match specific error patterns
filters:
  - field: message
    operator: REGEX
    value: "error.*0x[0-9a-fA-F]+"  # Errors with hex codes
```

## Combining with Other Options

Filters work alongside other ostrace options:

```bash
# Filter by process AND content
ios ostrace --process SpringBoard --filter-config ui-errors.yaml

# With specific PID and filter
ios ostrace --pid 35 --filter "animation"

# Archive filtered logs
ios ostrace --archive --filter-config important-logs.yaml
```

## Performance Considerations

- Filters are applied client-side after receiving logs from the device
- Complex regex patterns may impact performance with high log volumes
- Consider using process filtering (`--process` or `--pid`) first to reduce log volume before content filtering

## Tips

1. Start with simple filters and gradually add complexity
2. Use `--nojson` for human-readable output when testing filters
3. Test regex patterns with a tool like regex101.com before using
4. Combine field filters for more precise matching
5. Save commonly used filters in YAML files for reuse
