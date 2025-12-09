# DockerGuard

DockerGuard is a static vulnerability analysis tool for Dockerfiles. It analyzes Dockerfiles for security misconfigurations, vulnerabilities, and leaked secrets before building images.

This project is for CS2630, Systems Security at Harvard University.

## Features

- **Static Analysis**: Analyzes Dockerfiles for security issues before building images
- **Comprehensive Rule Engine**: 12+ built-in security rules covering:
  - User privileges and root access
  - Secret management
  - Package manager security
  - Image tagging best practices
  - File operations (COPY vs ADD)
  - Container configuration
- **Secret Detection**: Pattern-based detection of:
  - AWS access keys
  - API keys
  - Private keys (PEM format)
  - Passwords in environment variables
- **Base Image Analysis**: Reconstructs base images from Dockerfile and performs the same analysis
- **User Configuration**: Configurable rules and severity levels
- **CI/CD Ready**: Command-line tool that can be integrated into build pipelines

## Prerequisites

- Go 1.21 or later
- Git

## Setup

1. **Clone the repository**:

   ```bash
   git clone git@github.com:willcbelcher/DockerGuard.git
   cd DockerGuard
   ```

2. **Install dependencies**:

   ```bash
   go mod download
   go mod tidy
   ```

   This will download all dependencies and generate the `go.sum` file.

3. **Build the project**:

   ```bash
   go build -o dockerguard ./cmd/dockerguard
   ```

   Or install it directly:

   ```bash
   go install ./cmd/dockerguard
   ```

4. **Verify installation**:
   ```bash
   ./dockerguard --help
   ```

### Troubleshooting

If the `dockerguard` binary is not created after running `go build`:

1. **Check for build errors**: Make sure you're running the command from the project root directory:

   ```bash
   cd /path/to/DockerGuard
   go build -o dockerguard ./cmd/dockerguard
   ```

2. **Check for compilation errors**: If there are any errors, they will be displayed. Common issues:

   - Missing dependencies: Run `go mod tidy` again
   - Import errors: Make sure all files are saved

3. **Verify the binary was created**:

   ```bash
   ls -la dockerguard
   ```

4. **Try building with verbose output**:

   ```bash
   go build -v -o dockerguard ./cmd/dockerguard
   ```

5. **Alternative: Use go install** (installs to `$GOPATH/bin` or `$GOBIN`):
   ```bash
   go install ./cmd/dockerguard
   # Then run: dockerguard --help
   ```

## Usage

### Basic Usage

Analyze a Dockerfile:

```bash
./dockerguard -f Dockerfile
```

### Options

- `-f, --file`: Path to Dockerfile to analyze (default: "Dockerfile")
- `-c, --config`: Path to config file (optional)
- `-v, --verbose`: Enable verbose output

### Examples

```bash
# Analyze default Dockerfile
./dockerguard

# Analyze a specific Dockerfile
./dockerguard -f path/to/Dockerfile

# Enable verbose output
./dockerguard -v -f Dockerfile

# Use a configuration file
./dockerguard -f Dockerfile -c examples/dockerguard-config.yml

# Analyze example Dockerfile
./dockerguard -f examples/Dockerfile.example
```

### Example Output

```
[high] ROOT_USER: No USER instruction found - container will run as root
[critical] SECRET_ENV_ARG: Potential secret found in ENV instruction
  Line 5: ENV API_KEY=sk_live_1234567890abcdef
[medium] BASE_IMAGE_LATEST: Base image uses 'latest' tag or no tag specified
[critical] SECRET: Potential AWS Access Key detected
  Line 5: ENV API_KEY=sk_live_1234567890abcdef
[medium] ADD_INSTEAD_OF_COPY: Use COPY instead of ADD for local files
  Line 8: ADD app.py /app/
[low] MISSING_HEALTHCHECK: Consider adding HEALTHCHECK instruction for better container orchestration
```

## Project Structure

```
DockerGuard/
├── cmd/
│   └── dockerguard/      # Main CLI entry point
├── internal/
│   ├── analyzer/         # Core analysis engine (orchestrates all checks)
│   ├── cli/              # CLI command definitions (Cobra-based)
│   ├── dockerfile/       # Dockerfile parser (converts text to structured format, reconstructs base images)
│   ├── config/           # Configuration file parsing
│   ├── registry/         # Docker Registry API client (base image vulnerability checks)
│   ├── rules/            # Security rule engine
│   │   ├── engine.go     # Rule engine and rule definitions
│   │   └── helpers.go    # Helper functions for rule creation
│   └── types/            # Shared types (prevents import cycles)
├── examples/             # Example Dockerfiles for testing
├── sample_data/          # Sample Dockerfiles from real projects
├── go.mod                # Go module definition
├── Makefile              # Build automation
└── README.md
```

### Architecture Overview

1. **Entry Point** (`cmd/dockerguard/main.go`): Initializes CLI and handles errors
2. **CLI Layer** (`internal/cli/`): Parses user input, invokes analyzer, formats output
3. **Orchestration Layer** (`internal/analyzer/`): Coordinates all analysis components
4. **Analysis Components**:
   - **Parser** (`internal/dockerfile/`): Converts Dockerfile text to structured data
   - **Rule Checker** (`internal/rules/`): Executes security rules
   - **Registry Client** (`internal/registry/`): Base image vulnerability checks
   - **Configuration Parser** (`internal/config/`): Parses configuration file
5. **Shared Types** (`internal/types/`): Common data structures

## Security Rules

DockerGuard includes a comprehensive set of built-in security rules organized by severity. The rule engine is designed to be easily extensible.

### Rule Categories

#### Critical Severity
- **SECRET_ENV_ARG**: Secrets should not be hardcoded in ENV/ARG instructions
  - Detects potential secrets in environment variables and build arguments
  - Keywords: password, secret, key, token, api_key, credential, auth
  - Checks
    - **AWS Access Keys**: `AKIA[0-9A-Z]{16}` pattern
    - **API Keys**: Generic patterns for `api_key`, `apikey` with values
    - **Private Keys**: PEM format private keys (RSA, DSA, EC, OpenSSH)
    - **Passwords**: Password patterns in environment variables

- #### High Severity
- **ROOT_USER**: Container should not run as root user
  - Checks if container runs as root (UID 0) or if no USER instruction is present
- **RUN_PRIV_ESC**: RUN instructions should not contain privilege escalation
  - Detects use of `sudo` or `su` commands in RUN instructions

- #### Medium Severity
- **BASE_IMAGE_LATEST**: Base image should not use 'latest' tag
  - Warns when base image uses `:latest` tag or no tag (reduces reproducibility)
- **PKG_MGR_BEST_PRACTICE**: Package managers should use security best practices
  - Checks for `apt-get install` without `--no-install-recommends` flag
- **UNVERIFIED_DOWNLOAD**: Downloads should be verified with checksums or signatures
  - Warns when `curl` or `wget` are used without verification (checksum, GPG, etc.)
- **ADD_INSTEAD_OF_COPY**: Use COPY instead of ADD for local files
  - Recommends COPY over ADD unless ADD's special features (URLs, tar extraction) are needed
- **WORKDIR_ROOT**: WORKDIR should not be set to root directory
  - Warns when WORKDIR is set to `/` or `/root`

- #### Low Severity
- **APT_INSTALL_NO_UPDATE**: apt-get install should be combined with apt-get update
  - Best practice reminder for package manager usage
- **EXPOSE_DOCUMENTATION**: EXPOSE should be documented and necessary
  - Informational check for exposed ports
- **MISSING_HEALTHCHECK**: Consider adding HEALTHCHECK instruction
  - Recommends adding healthcheck for better container orchestration
- **CMD_NOT_EXEC_FORM**: CMD/ENTRYPOINT should use exec form (JSON array)
  - Recommends exec form `["cmd", "arg"]` over shell form for better signal handling

### Extending Rules

The rule engine is designed for easy extension. To add a new rule:

1. **Create a check function** in `internal/rules/engine.go`:

   ```go
   func (e *Engine) checkYourNewRule(df *dockerfile.Dockerfile) []types.Result {
       var results []types.Result
       // Your rule logic here
       return results
   }
   ```

2. **Register the rule** in `registerDefaultRules()`:

   ```go
   e.registerRule("CUSTOM_RULE_ID", "Your rule description", "severity", e.checkYourNewRule)
   ```

3. **Use helper functions** from `helpers.go`:
   - `findInstructions()` - Find specific instruction types
   - `hasInstruction()` - Check if instruction exists
   - `getEffectiveUser()` - Get the effective user
   - `isRootUser()` - Check if user is root
   - `createResult()` - Create standardized results

Example rule implementation:

```go
func (e *Engine) checkExampleRule(df *dockerfile.Dockerfile) []types.Result {
    var results []types.Result

    for _, inst := range df.Instructions {
        if inst.Type == "RUN" && strings.Contains(inst.Args, "insecure-pattern") {
            results = append(results, createResult(
                "CUSTOM_RULE_ID",
                "high",
                "Found insecure pattern in RUN instruction",
                inst.Line,
                inst.Raw,
            ))
        }
    }

    return results
}
```

## Quick Reference

### Rule IDs

| ID | Severity | Description |
|----|----------|-------------|
| ROOT_USER | High | Container runs as root user |
| SECRET_ENV_ARG | Critical | Hardcoded secrets in ENV/ARG |
| BASE_IMAGE_LATEST | Medium | Base image uses 'latest' tag |
| RUN_PRIV_ESC | High | Privilege escalation in RUN |
| PKG_MGR_BEST_PRACTICE | Medium | Insecure package manager usage |
| APT_INSTALL_NO_UPDATE | Low | apt-get update best practice |
| UNVERIFIED_DOWNLOAD | Medium | Unverified downloads |
| ADD_INSTEAD_OF_COPY | Medium | ADD vs COPY usage |
| EXPOSE_DOCUMENTATION | Low | EXPOSE port documentation |
| MISSING_HEALTHCHECK | Low | Missing HEALTHCHECK |
| WORKDIR_ROOT | Medium | WORKDIR set to root |
| CMD_NOT_EXEC_FORM | Low | CMD/ENTRYPOINT form |
| SECRET | Critical/High | Secret pattern detected |

### Helper Functions Reference

When creating custom rules, use these helper functions from `helpers.go`:

- `findInstructions(df, type)` - Find all instructions of a type
- `hasInstruction(df, type)` - Check if instruction type exists
- `getEffectiveUser(df)` - Get the effective user (returns user, line, context)
- `isRootUser(user)` - Check if user string is root
- `containsPattern(text, patterns)` - Check if text matches regex patterns
- `createResult(id, severity, message, line, context)` - Create standardized result
- `checkRunInstruction(inst)` - Check RUN instruction for common issues

## Contributing

This is a research project for COMPSCI 2630 taught by Professor James Mickens at Harvard University. Contributions and improvements are welcome!

## Authors

- William Belcher (wbelcher@mba2026.hbs.edu)
- Valerie Chen (vchen@mba2026.hbs.edu)
