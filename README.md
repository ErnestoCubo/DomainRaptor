# 🦖 DomainRaptor

![DomainRaptor](DomainRaptor.jpg)

**DomainRaptor** is a cyber intelligence tool for extracting and enriching data from massive text files. It extracts IPs, domains, URLs using regex patterns and enriches them with Shodan intelligence.

## 🚀 Features

- **Pattern Extraction**: Extract IPv4, IPv6, domains, subdomains, and URLs from text files
- **Multi-threading**: Process large files efficiently using parallel execution
- **Shodan Integration**: Enrich extracted domains with public exposure data
- **Colored Output**: Beautiful JSON output with syntax highlighting

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/ErnestoCubo/DomainRaptor.git
cd DomainRaptor

# Install dependencies
pip install shodan colorama pygments
```

## 🔧 Usage

```bash
python DomainRaptor.py -e <EXPRESSION> -i <INPUT_FILE> [-t THREADS] [-a API_KEY]
```

### Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-e, --expression` | Pattern type to extract (see below) | ✅ |
| `-i, --input_file` | Path to the input file | ✅ |
| `-t, --threads` | Number of threads (default: 10) | ❌ |
| `-a, --api_key` | Shodan API key (required for option 2) | ❌ |
| `-f, --format` | Export format (coming soon) | ❌ |

### Expression Options

| Option | Description | Example Match |
|--------|-------------|---------------|
| `1` | IPv4 addresses | `192.168.1.1` |
| `2` | Domains & Subdomains | `www.example.com` |
| `3` | URLs (all protocols) | `https://example.com/path` |
| `4` | IPv6 addresses | `2001:0db8:85a3::8a2e:0370:7334` |

### Examples

```bash
# Extract IPv4 addresses
python DomainRaptor.py -e 1 -i targets.txt

# Extract domains and enrich with Shodan
python DomainRaptor.py -e 2 -i urls.txt -a YOUR_SHODAN_API_KEY

# Extract all URLs with 20 threads
python DomainRaptor.py -e 3 -i logs.txt -t 20
```

## 📁 Project Structure

```
DomainRaptor/
├── DomainRaptor.py          # Main entry point
├── patterns.txt             # Sample input file
└── modules/
    ├── cli/                 # Command line interface
    │   └── args_parser.py
    ├── core/                # Core processing
    │   ├── regex_engine.py  # Pattern matching
    │   └── data_transformer.py
    ├── enrichment/          # External API integrations
    │   ├── shodan_client.py
    │   └── whois_client.py  # (Coming soon)
    ├── output/              # Output formatting
    │   └── printer.py
    └── utils/               # Utilities
        └── logger.py
```

## 🗺️ Roadmap

- [x] IPv4 extraction
- [x] Domain/Subdomain extraction
- [x] URL extraction
- [x] Shodan integration
- [ ] IPv6 extraction (regex fix needed)
- [ ] WHOIS lookup integration
- [ ] Export to JSON/CSV
- [ ] Passive port scanning
- [ ] Phishing domain detection
- [ ] HoneyPot detection

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## ⚠️ Disclaimer

This tool is intended for legal security research and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before scanning any targets.
