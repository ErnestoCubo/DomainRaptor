# 📦 Installation Guide

This guide covers all methods to install DomainRaptor on your system.

---

## 📋 Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| Python | 3.10+ | 3.12+ |
| RAM | 512 MB | 2 GB |
| Disk Space | 100 MB | 500 MB |
| OS | Linux, macOS, Windows | Linux |

### Required Software

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **git** (for development installation)

Check your Python version:

```bash
python --version
# or
python3 --version
```

---

## 🚀 Installation Methods

### Method 1: Install from PyPI (Recommended)

The simplest way to install DomainRaptor:

```bash
pip install domainraptor
```

Or with a specific Python version:

```bash
python3.12 -m pip install domainraptor
```

### Method 2: Install from Source

Clone the repository and install in development mode:

```bash
# Clone the repository
git clone https://github.com/ErnestoCubo/DomainRaptor.git
cd DomainRaptor

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install in development mode
pip install -e .
```

### Method 3: Install with Development Dependencies

For contributors and developers:

```bash
git clone https://github.com/ErnestoCubo/DomainRaptor.git
cd DomainRaptor

python -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

### Method 4: Using pipx (Isolated Installation)

```bash
pipx install domainraptor
```

---

## ✅ Verify Installation

After installation, verify that DomainRaptor is working:

```bash
# Check version
domainraptor --version
```

Expected output:

```
DomainRaptor v0.2.0
```

Run a quick test:

```bash
domainraptor --help
```

---

## ⚙️ Post-Installation Setup

### 1. Initialize Configuration

Set up your configuration interactively:

```bash
domainraptor config init
```

This will guide you through:

- Creating the configuration directory
- Setting up API keys (optional)
- Configuring default settings

### 2. Configure API Keys (Optional but Recommended)

For enhanced functionality, configure your API keys:

```bash
# Shodan API (for port scanning and service detection)
domainraptor config set SHODAN_API_KEY your_shodan_api_key_here

# VirusTotal API (for malware analysis)
domainraptor config set VIRUSTOTAL_API_KEY your_virustotal_api_key_here

# SecurityTrails API (for subdomain enumeration)
domainraptor config set SECURITYTRAILS_API_KEY your_securitytrails_api_key_here

# Censys API (for certificate search)
domainraptor config set CENSYS_API_KEY your_censys_api_key_here
```

### 3. Verify Configuration

```bash
# List configured API keys
domainraptor config list

# Test API key validity
domainraptor config test
```

---

## 📁 Configuration Paths

DomainRaptor stores its configuration and data in the following locations:

| Platform | Configuration Path |
|----------|-------------------|
| Linux | `~/.domainraptor/` |
| macOS | `~/.domainraptor/` |
| Windows | `%USERPROFILE%\.domainraptor\` |

### Directory Structure

```
~/.domainraptor/
├── .env                 # API keys and secrets
├── config.yaml          # User configuration
├── domainraptor.db      # SQLite database
└── reports/             # Generated reports
```

View your configuration paths:

```bash
domainraptor config path
```

---

## 🐳 Docker Installation (Coming Soon)

```bash
# Pull the image
docker pull ernestocubo/domainraptor:latest

# Run a scan
docker run --rm ernestocubo/domainraptor discover -T example.com
```

---

## 🔧 Troubleshooting Installation

### Common Issues

#### 1. Command not found

If `domainraptor` is not recognized:

```bash
# Check if installed
pip show domainraptor

# Add to PATH (Linux/macOS)
export PATH="$HOME/.local/bin:$PATH"

# Or run directly
python -m domainraptor --help
```

#### 2. Permission Denied

```bash
# Install for current user only
pip install --user domainraptor
```

#### 3. SSL Certificate Errors

```bash
# Update certificates
pip install --upgrade certifi
```

#### 4. Dependency Conflicts

```bash
# Create clean virtual environment
python -m venv fresh_venv
source fresh_venv/bin/activate
pip install domainraptor
```

---

## 🔄 Updating DomainRaptor

### From PyPI

```bash
pip install --upgrade domainraptor
```

### From Source

```bash
cd DomainRaptor
git pull origin main
pip install -e .
```

---

## 🗑️ Uninstallation

```bash
pip uninstall domainraptor
```

To also remove configuration and data:

```bash
rm -rf ~/.domainraptor
```

---

**← [Home](Home)** | **Next: [Quick Start Guide](Quick-Start) →**
