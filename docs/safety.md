# Safety guidelines

This tool performs **static analysis only**. Files are never executed and nothing is uploaded.

## Rules

1. **Never execute** the files you scan — not even in a sandbox from within this app.
2. Test with the **EICAR** test file first to confirm the pipeline works.
3. Use real samples from [MalwareBazaar](https://bazaar.abuse.ch/) **only inside an isolated VM** with no network access to production systems.
4. Do not commit malware samples to this repository. The `.gitignore` excludes `samples/` and `malware_samples/`.
5. Keep scan reports out of version control (excluded via `.gitignore`).

## Reporting a vulnerability

If you find a security issue in this project, please open a private security advisory via GitHub rather than a public issue.