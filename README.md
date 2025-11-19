# DockerGuard

DockerGuard is a static vulnerability analysis tool for Dockerfiles. It analyzes Dockerfiles for security misconfigurations, vulnerabilities, and leaked secrets before building images.

This project is for CS2630, Systems Security at Harvard University.

## Features

- **Static Analysis**: Analyzes Dockerfiles for security issues before building images
- **Rule Engine**: Configurable security rules for fine-grained control
- **Secret Detection**: Detects hardcoded secrets, API keys, passwords, and private keys
- **Base Image Analysis**: Checks base images for known vulnerabilities (via Docker Registry API)
- **CI/CD Ready**: Command-line tool that can be integrated into build pipelines

## Prerequisites

- Go 1.21 or later
- Git

## Setup

1. **Clone the repository** (if not already done):
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
- `-r, --rules`: Path to custom rules file (optional)
- `-v, --verbose`: Enable verbose output

### Examples

```bash
# Analyze default Dockerfile
./dockerguard

# Analyze a specific Dockerfile
./dockerguard -f path/to/Dockerfile

# Enable verbose output
./dockerguard -v -f Dockerfile
```

## Project Structure

```
DockerGuard/
├── cmd/
│   └── dockerguard/      # Main CLI entry point
├── internal/
│   ├── analyzer/         # Core analysis engine
│   ├── cli/              # CLI command definitions
│   ├── dockerfile/       # Dockerfile parser
│   ├── registry/         # Docker Registry API client
│   ├── rules/            # Security rule engine
│   └── secrets/          # Secret detection scanner
├── go.mod                # Go module definition
└── README.md
```

## Development

### Running Tests

```bash
go test ./...
```

### Building for Different Platforms

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o dockerguard-linux ./cmd/dockerguard

# macOS
GOOS=darwin GOARCH=amd64 go build -o dockerguard-macos ./cmd/dockerguard

# Windows
GOOS=windows GOARCH=amd64 go build -o dockerguard.exe ./cmd/dockerguard
```

## Security Rules

DockerGuard includes several built-in security rules:

- **DG001**: Container should not run as root user
- **DG002**: Secrets should not be hardcoded in ENV instructions
- **DG003**: Base image should not use 'latest' tag
- **SECRET**: Detects various secret patterns (AWS keys, API keys, private keys, passwords)

## Contributing

This is a research project for CS2630. Contributions and improvements are welcome!

## License

[To be determined]

## Authors

- William Belcher (wbelcher@mba2026.hbs.edu)
- Valerie Chen (vchen@mba2026.hbs.edu)
