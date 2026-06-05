# plugin-aws-ecr-image-policy

OPA policy bundle for AWS ECR container image compliance checks.

## Policies

| Policy | Description | Controls |
|--------|-------------|----------|
| `ecr_require_image_scan_complete` | Image must have a completed vulnerability scan | CC3.2, CC5.2, CC7.1, CC8.1 |
| `ecr_require_no_critical_image_findings` | Image must have zero CRITICAL severity findings | CC6.8, CC7.1, CC8.1 |
| `ecr_require_no_high_image_findings` | Image must not exceed the HIGH severity finding threshold | CC6.8, CC7.1, CC8.1 |
| `ecr_require_scan_findings_retrievable` | Image scan findings must be retrievable with severity data | CC6.8, CC7.1 |

## data.json reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_high_finding_count` | `number` | `0` | Maximum allowed HIGH severity findings |
