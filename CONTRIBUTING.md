# Contributing to OpenIronKey

Thank you for your interest in contributing! This project aims to provide modern Linux support for the IronKey S200 secure USB drive through reverse engineering and clean-room reimplementation.

## Ways to Contribute

### 🔬 Reverse Engineering (High Priority)
- **Nonce derivation**: The 12-byte session nonce for commands 6-13 is dynamically derived from previous responses. Analyze `ikpkcs11.dll` and `IronKey.exe` in Ghidra/IDA.
- **Unlock token derivation**: The 256-byte token sent to `WRITE_UNLOCK` uses PBKDF2-SHA256. Determine: iteration count, salt construction, key slot usage.
- **Crypto command mapping**: Map PKCS#11 mechanisms to SCSI `CRYPTO_OPERATION` subcodes.

### 💻 Code Contributions
- Complete PKCS#11 cryptographic operations (encrypt, sign, decrypt, verify)
- Add support for other IronKey models (D250, D300, Personal, Enterprise)
- Improve GTK4 GUI (device monitoring, applet management, settings persistence)
- Add unit tests and integration tests
- Improve documentation

### 📝 Documentation
- Protocol documentation in `docs/scsi_protocol.md`
- API documentation
- Usage examples
- Hardware compatibility matrix

## Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/openironkey
cd openironkey

# Install dev dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install
```

## Code Style

- **Python**: Black (line length 100), type hints required for public APIs
- **Commits**: Conventional Commits format (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`)
- **Branching**: `feat/*`, `fix/*`, `docs/*`, `refactor/*` from `main`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src/openironkey --cov-report=html

# Type checking
mypy src/
```

## Pull Request Process

1. **Create issue first** for significant changes (discuss approach)
2. **Branch from `main`** with descriptive name
3. **Write tests** for new functionality
4. **Update documentation** if APIs change
5. **Run full test suite** locally
6. **Submit PR** with clear description

### PR Requirements
- [ ] All tests pass
- [ ] Type checking passes (`mypy`)
- [ ] Code formatted (`black`)
- [ ] Documentation updated
- [ ] Changelog entry (for user-facing changes)

## Reverse Engineering Guidelines

### Legal & Ethical
- **Clean room only**: Do not decompile and copy code directly. Document behavior, reimplement from specs.
- **Interoperability exception**: Reverse engineering for interoperability is protected in many jurisdictions (EU Directive 2009/24, US DMCA 1201(f)).
- **No credential extraction**: Never commit PINs, keys, certificates, or extracted secrets.

### Tools
- **Static analysis**: Ghidra (free), IDA Pro, Binary Ninja
- **Dynamic analysis**: `strace`, `ltrace`, `sg_raw`, USBpcap/Wireshark
- **Protocol capture**: Use the provided `src/scsi/debug_sequence.py` as template

### Documentation Standards
When documenting RE findings:
- Include exact command bytes (CDB hex dump)
- Note data direction (IN/OUT)
- Record sense codes on failure
- Describe parameter roles
- Link to Windows binary offsets if applicable

## Hardware Compatibility

| Model | VID:PID | Status | Notes |
|-------|---------|--------|-------|
| S200 2GB | 1953:0202 | 🟢 Primary target | Tested |
| S250 | 1953:???? | ⚪ Unknown | |
| D250 | 1953:???? | ⚪ Unknown | |
| D300 | 1953:???? | ⚪ Unknown | |
| Personal | 1953:???? | ⚪ Unknown | |
| Enterprise | 1953:???? | ⚪ Unknown | |
| Keypad 200 | 1953:???? | ⚪ Unknown | Hardware keypad variant |

If you have other models, please report VID:PID and test basic INQUIRY.

## Communication

- **Issues**: Bug reports, feature requests, RE findings
- **Discussions**: Design decisions, architecture, protocol analysis
- **Security**: Report vulnerabilities privately via GitHub Security Advisories

## Code of Conduct

Be respectful, constructive, and inclusive. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Questions?

Open a GitHub Discussion or issue. For reverse engineering questions, include:
- Tool used (Ghidra/IDA/other)
- Binary analyzed (filename, SHA256)
- Specific function/offset
- Your hypothesis

---

*Thank you for helping liberate the IronKey!*