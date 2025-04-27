# SecurePip

SecurePip is a secure package installer and analyzer for Python that helps you safely install and manage Python packages while providing detailed security analysis and vulnerability reports. It leverages Ollama & Gemma AI to use your local AI to do rudamentary security scans over your python dependencies as they install or provided a requirements.txt file.

## Features

- 🔍 **Security Analysis**: Analyzes packages for vulnerabilities before installation
- 📊 **Detailed Reports**: Generates comprehensive HTML reports of package analysis
- 🛡️ **Safe Installation**: Prevents installation of potentially harmful packages
- 🔄 **Cache Support**: Caches analysis results for faster subsequent runs
- 📦 **Requirements Support**: Works with requirements.txt files
- 🤖 **AI-Powered Analysis**: Uses Ollama for advanced package analysis

## Installation

### Local Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/securepip.git
cd securepip

# Run the installation script
./install.sh
```

### PyPI Installation (Coming Soon)

```bash
pip install securepip
```

## Usage

### Basic Package Installation

```bash
# Install a package
securepip install requests

# Install a specific version
securepip install requests==2.31.0

# Install with force (ignore warnings)
securepip install --force requests
```

### Package Analysis (Dry Run)

```bash
# Analyze a package without installing (always generates report)
securepip analyze requests

# Analyze with specific version
securepip analyze requests==2.31.0

# Analyze from requirements file
securepip analyze -r requirements.txt

# Analyze with custom Ollama model
securepip analyze --model llama2:7b requests

# Analyze with disabled cache
securepip analyze --no-cache requests

# Force analysis despite warnings
securepip analyze --force requests
```

### Requirements File Support

```bash
# Install from requirements file
securepip install -r requirements.txt

# Analyze from requirements file
securepip analyze -r requirements.txt
```

### Advanced Options

```bash
# Disable cache
securepip install --no-cache requests

# Specify Ollama model
securepip install --model llama2:7b requests

# Generate HTML report (for install command)
securepip install --report requests
```

## Development

### Setup Development Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .
```

### Running Tests

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests
pytest
```

### Building and Deploying

```bash
# Build and deploy to PyPI
./deploy.sh
```

## Configuration

SecurePip can be configured through command-line arguments:

- `--force`: Force operation despite warnings
- `--no-cache`: Disable analysis cache
- `--model`: Specify Ollama model to use
- `--report`: Generate HTML report (for install command)
- `-r/--requirement`: Install from requirements file

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Ollama](https://ollama.ai/) for providing the AI analysis capabilities
- [pip](https://pip.pypa.io/) for inspiration and package management features 