# Suspicious File Scanner

A **local desktop app** for static analysis of suspicious files. Files are never executed and nothing is ever uploaded — everything runs on your machine. Built for cybersec learners who want to inspect suspicious files safely and see what malware looks like from the inside.

## Features (MVP)

- Drag & drop a file
- MD5 / SHA1 / SHA256 hashes + file type detection
- Strings extractor + entropy calculation (flags packed/encrypted files)
- PE and ELF header parsing: sections and imports
- Flag suspicious imports (e.g. `VirtualAlloc`, `WriteProcessMemory`)
- Simple risk score with an explanation of why
- Export report to JSON / PDF
- YARA rule matching
- Scan history (local SQLite, bounded retention)
- Relationship graph between files

## Safety

- **Never execute** the files you scan.
- Test with the EICAR test file first.
- Use real samples from [MalwareBazaar](https://bazaar.abuse.ch/) **only inside an isolated VM**.
- See [docs/safety.md](docs/safety.md).

## Stack

Python + [Flet](https://flet.dev) for the UI, plus `pefile`, `pyelftools`, `hashlib`, and `yara-python`. Parsers may move to Rust later for speed.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m suspicious_file_scanner.main
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes go through PRs.

## License

MIT — see [LICENSE](LICENSE).