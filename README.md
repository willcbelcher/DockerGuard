# DockerGuard

DockerGuard is a static vulnerability analysis command-line tool for Dockerfiles. It analyzes Dockerfiles for security misconfigurations, vulnerabilities, and leaked secrets before building images.

This project is for CS2630, Systems Security at Harvard University.

## Features

- **11 built-in security rules** covering secrets, privileges, package managers, and best practices
- **Base image analysis** - recursively checks base images from Docker registry
- **Configurable rules** - disable rules or change severity via YAML config

## Installation

```bash
git clone git@github.com:willcbelcher/DockerGuard.git
cd DockerGuard
go mod download
go build -o dockerguard ./cmd/dockerguard
```

## Usage

```bash
# Analyze a Dockerfile
./dockerguard -f Dockerfile

# With verbose output (shows low severity warnings)
./dockerguard -v -f Dockerfile

# With custom configuration
./dockerguard -f Dockerfile -c config.yaml
```

### Options

- `-f, --file`: Path to Dockerfile (default: "Dockerfile")
- `-c, --config`: Path to YAML config file (optional)
- `-v, --verbose`: Enable verbose output

## Configuration

Create a YAML file to disable rules or change severity levels:

```yaml
rules:
  ROOT_USER:
    disabled: true
  SECRET:
    severity: "low"
  BASE_IMAGE_LATEST:
    disabled: true
```

Available severity levels: `critical`, `high`, `medium`, `low`

## Security Rules (Default)

| Rule ID                   | Severity      | Description                                                             |
| ------------------------- | ------------- | ----------------------------------------------------------------------- |
| **SECRET**                | Critical/High | Detects hardcoded secrets (AWS keys, API keys, private keys, passwords) |
| **ROOT_USER**             | High          | Container runs as root user                                             |
| **RUN_PRIV_ESC**          | High          | Privilege escalation in RUN instructions (sudo/su)                      |
| **CURL_BASHING**          | High          | Piping curl/wget output into shell without verification                 |
| **BASE_IMAGE_LATEST**     | Medium        | Base image uses 'latest' tag                                            |
| **PKG_MGR_BEST_PRACTICE** | Medium        | Insecure package manager usage                                          |
| **ADD_INSTEAD_OF_COPY**   | Medium        | Using ADD instead of COPY for local files                               |
| **WORKDIR_ROOT**          | Medium        | WORKDIR set to root directory                                           |
| **APT_INSTALL_NO_UPDATE** | Low           | apt-get install without update                                          |
| **EXPOSE_DOCUMENTATION**  | Low           | EXPOSE port documentation                                               |
| **MISSING_HEALTHCHECK**   | Low           | Missing HEALTHCHECK instruction                                         |

Rules were inspired by ideas presented in the following resources:

- **[Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)** — _OWASP_

- **[docker security best practices from the dockerfile](https://cloudberry.engineering/article/dockerfile-security-best-practices/)** — _Gianluca Brindisi_

- **[Dockerfile Security Best Practices: How to Build Secure Containers](https://medium.com/@IamLucif3r/dockerfile-security-best-practices-how-to-build-secure-containers-a4fc25c4f2be)** — _Anmol Singh Yadav_

## Example Output

```
[high] ROOT_USER: No USER instruction found - container will run as root
[critical] SECRET: Potential secret found in ENV instruction
  Line 5: ENV API_KEY=sk_live_1234567890abcdef
[medium] BASE_IMAGE_LATEST: Base image uses 'latest' tag or no tag specified
[medium] ADD_INSTEAD_OF_COPY: Use COPY instead of ADD for local files
  Line 8: ADD app.py /app/
```

## Adding Custom Rules

To add a new rule, modify `internal/rules/checker.go`:

1. Create a check function:

```go
func (e *RuleChecker) checkYourRule(df *dockerfile.Dockerfile) []types.Result {
    var results []types.Result
    // Rule logic here
    return results
}
```

2. Register it in `registerDefaultRules()`:

```go
e.registerRule("RULE_ID", "Description", "severity", e.checkYourRule)
```

See `internal/rules/helpers.go` for helper functions like `findInstructions()`, `createResult()`, etc.

## Project Structure

```
DockerGuard/
├── cmd/dockerguard/      # CLI entry point
├── internal/
│   ├── analyzer/         # Analysis orchestrator
│   ├── cli/              # CLI commands (Cobra)
│   ├── config/           # Configuration parsing
│   ├── dockerfile/       # Dockerfile parser
│   ├── registry/         # Docker Registry API client
│   ├── rules/            # Security rules engine
│   └── types/            # Shared types
├── examples/             # Example Dockerfiles
└── sample_data/          # Sample Dockerfiles
```

## Contributing

This is a research project for COMPSCI 2630 taught by Professor James Mickens at Harvard University. Contributions welcome!

## Authors

- William Belcher (wbelcher@mba2026.hbs.edu)
- Valerie Chen (vchen@mba2026.hbs.edu)
