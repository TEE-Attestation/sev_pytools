# sev_pytools

A Python library and CLI tool for AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation report verification. This project provides comprehensive functionality for parsing, validating, and verifying SEV-SNP attestation reports, including cryptographic signature verification, certificate chain validation, and policy-based security enforcement.

## Overview

AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) is a confidential computing technology that provides hardware-assisted isolation and memory encryption for virtual machines. SEV-SNP attestation reports are cryptographic evidence that prove the integrity, authenticity, and security posture of a SEV-SNP enabled system.

### Key Features

- **Complete Report Parsing**: Parse SEV-SNP attestation reports with detailed structure extraction
- **Cryptographic Verification**: ECDSA signature verification for attestation report authentication
- **Certificate Chain Validation**: Full X.509 certificate chain verification with CRL checking
- **Policy Validation Framework**: Flexible JSON-based policy engine for security requirement enforcement
- **AMD KDS Integration**: Automatic fetching of certificates from AMD Key Distribution Service
- **Guest Policy Management**: Comprehensive guest policy flag interpretation and validation
- **Platform Information**: Platform capability and feature analysis
- **Comprehensive Logging**: Detailed verification steps with configurable logging levels
- **CLI Tools**: Ready-to-use command-line utilities for report inspection and verification
- **TAS Trust Decision**: `sev-verify-tas` attests a running TEE Attestation Service (TAS) instance before you trust it with secrets

## Architecture

The library is organized as follows:

### Core Components

- **`attestation_report.py`**: AMD SEV-SNP attestation report parsing and data structure definitions
  - `AttestationReport`: Complete report structure parsing and representation
  - `TcbVersion`: Trusted Computing Base version handling
  - `Cpuid`: CPU identification and feature parsing

- **`verify.py`**: Complete attestation verification pipeline
  - Report signature verification using certificate chain
  - Certificate chain validation to AMD root CA
  - Policy-based validation with configurable rules
  - Comprehensive security posture assessment

### Supporting Modules

- **`certs.py`**: Certificate management and verification utilities for AMD SEV-SNP attestation
- **`guest_policy.py`**: Guest policy management and validation for AMD SEV-SNP attestation
- **`platform_info.py`**: Platform information parsing and management for AMD SEV-SNP attestation
- **`policy.py`**: Policy validation framework for AMD SEV-SNP attestation reports
- **`signature.py`**: Digital signature handling for AMD SEV-SNP attestation reports
- **`fetch.py`**: Certificate fetching utilities for AMD SEV-SNP attestation reports
- **`print_report.py`**: Command-line utility for displaying AMD SEV-SNP attestation report details
- **`sev_logging.py`**: Centralized logging configuration for sev_pytools package

## Project Structure

## Installation

### Requirements

- Python 3.6+
- Dependencies (automatically installed):
  - `cryptography >= 39.0.0`
  - `requests >= 2.25.0`

### Install from Source

```bash
git clone https://github.com/TEE-Attestation/sev_pytools.git
cd sev_pytools
pip install .
```

### Uninstallation

```bash
pip uninstall sev_pytools
```

## Usage

### Command Line Tools

#### Print Attestation Report Details

Display the contents of an AMD SEV-SNP attestation report in human-readable format:

```bash
# Using the installed command
sev-print -f report.bin

# With debug output for detailed parsing information
sev-print -f report.bin -d

# Using Python module directly
python -m sev_pytools.print_report -f report.bin
```

**Options:**
- `-f, --file`: Path to the attestation report file (default: `report.bin`)
- `-d, --debug`: Enable debug mode for additional output

#### Verify Attestation Report Authenticity

Perform complete cryptographic verification of an AMD SEV-SNP attestation report:

```bash
# Basic verification
sev-verify -f report.bin -c ./certs/

# Verbose verification with detailed steps
sev-verify -f report.bin -c ./certs/ -v

# Show report data after successful verification
sev-verify -f report.bin -c ./certs/ -r

# With policy validation
sev-verify -f report.bin -c ./certs/ -q policy.json
```

**Options:**
- `-f, --file`: Path to the attestation report file (default: `report.bin`)
- `-c, --certs`: Path to the directory containing certificates (default: the [certificate cache](#certificate-cache))
- `-d, --debug`: Enable debug mode for additional output (automatically enables verbose mode)
- `-v, --verbose`: Enable verbose mode for detailed information
- `-r, --reportdata`: Print report data at the end of successful verification
- `-p, --processor`: Processor model (e.g., milan, genoa) used only if no certificates found (default: `genoa`)
- `-q, --policy`: Path to the policy file for validating the report against security policies (optional)

#### Fetch Certificates from AMD KDS

Retrieve certificates from the AMD Key Distribution Service:

```bash
# Fetch ARK and ASK certificates
sev-fetch ca -p genoa -e PEM -d ./certs/

# Fetch VCEK certificate for a specific report
sev-fetch vcek -p genoa -e PEM -d ./certs/ -r report.bin
```

**Options:**
- `ca`: Fetch ARK and ASK certificates
- `vcek`: Fetch VCEK certificate
- `-p, --processor`: Processor model (e.g., milan, genoa) (default: `genoa`)
- `-e, --encoding`: Certificate encoding format (PEM or DER)
- `-d, --dir`: Directory to save the fetched certificates (default: the [certificate cache](#certificate-cache))
- `--endorser`: Endorser type (vcek or vlek) for fetching VCEK or VLEK certificates
- `-r, --report`: Path to the attestation report file (required for fetching VCEK)

#### Certificate Cache

All commands read and write certificates in the same directory unless `-c`/`-d`
says otherwise: `$SEV_PYTOOLS_CERTS_DIR` if set, else `$XDG_CACHE_HOME/sev_pytools`,
else `~/.cache/sev_pytools`. So `sev-fetch vcek -r report.bin` followed by
`sev-verify -f report.bin` just works, and nothing is written into the current
directory.

#### Verify a TAS Instance (`sev-verify-tas`)

Decide whether a TEE Attestation Service runs inside a genuine, correctly
measured AMD SEV-SNP confidential VM — for example before an operator hands it
secrets during setup. The tool requests TAS's TAS-attestation report
(`POST /attest/v0/report` with `{"nonce": …}`), verifies it locally and ends with
one of three verdicts on its last line:

| Last line       | Exit | Meaning                                                                 |
|-----------------|------|-------------------------------------------------------------------------|
| `TRUSTED`       | 0    | Genuine SEV-SNP report, bound to this connection, policy satisfied      |
| `NOT TRUSTED`   | 1    | Evidence against TAS: bad signature/measurement/policy, VLEK-signed, proxy detected, or TAS says it is not a CVM |
| `UNDETERMINED`  | 2    | No verdict possible: TAS unreachable or busy (HTTP 429/503), key required, AMD KDS unreachable with a cold cache, bad arguments |

Scripts should treat anything but exit 0 as "do not proceed", and only retry on 2.

```bash
# Expected launch measurement from the TAS image (e.g. sev-snp-measure output)
sev-verify-tas https://tas.example.com -m cf9bcad1612a34b8...055627

# Require a minimum platform TCB (any subset of bl/tee/snp/ucode) and an
# up-to-date platform (reported TCB == current TCB; otherwise only a warning)
sev-verify-tas https://tas.example.com -m <hex> --min-tcb bl=9,tee=0,snp=23,ucode=72 --require-tcb-match

# TAS configured with TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY=true
sev-verify-tas https://tas.example.com -m <hex> -k "$TAS_MANAGEMENT_API_KEY"

# Policy file for everything else; -m still overrides the file's measurement
sev-verify-tas https://tas.example.com -q policy.json -m <hex>
```

What is checked:

1. **Freshness and TLS binding** — the report's `REPORT_DATA` must equal
   `SHA-512("TAS-attest/v1" ‖ nonce ‖ SHA-256(TLS leaf certificate))`, where the certificate is
   the one on the very connection that delivered the report. A plain proxy that
   terminates TLS and relays a genuine CVM's report is therefore detected. The
   TLS certificate does not need to chain to a CA you trust — attestation vouches
   for it (pass `--ca-file` to validate it conventionally as well).
2. **Signature chain** — the report must be VCEK-signed; built-in AMD root → ASK
   → VCEK → report, plus a CRL that is within its validity period.
3. **Trust policy** — expected `--measurement`, `--vmpl` (default 0), debug
   disabled (always; a debug-enabled guest is readable by the hypervisor),
   migration disabled (`--allow-migration` to relax), report version ≥ 2,
   optional `--min-tcb` floor applied to both the reported and the current TCB.
   Alternatively supply a full policy file with `--policy`.

Certificate cache (`-c/--certs`, default: the [certificate cache](#certificate-cache)):
`crl.pem` plus one `<chip id>-<reported TCB>/vcek.pem` per platform, so one
directory serves many TAS instances and a firmware update never reuses a stale
VCEK. The VCEK comes from the hypervisor's certificate table in the response
when present, else the cache, else the AMD KDS; the CRL is refreshed from the
KDS once it expires (AMD issues them for a few weeks). The table is only an
optimisation: entries that are not AMD-issued or not for the report's chip and
TCB (typically a host whose table was not refreshed after a firmware update)
are ignored with a warning, never turned into a verdict. A populated cache with
a current CRL works fully offline. Version 2 reports carry no CPUID, so pass
`-p/--processor` for non-Genoa platforms.

`--save-report FILE` keeps the raw report for `sev-print`. The response's
`provider` must be `sev_guest`; a TAS running on another TEE is reported as
NOT TRUSTED by this tool.

### Python API

#### Basic Report Parsing

```python
from sev_pytools import AttestationReport

# Load and parse an attestation report
with open('report.bin', 'rb') as f:
    report_data = f.read()

report = AttestationReport.unpack(report_data)

# Access report components
print(f"Report version: {report.version}")
print(f"Guest SVN: {report.guest_svn}")
print(f"Policy: {report.policy}")

# Display report details
report.log_details()
```

#### Complete Report Verification

```python
from sev_pytools.verify import verify_report
from sev_pytools import AttestationReport

# Load report
with open('report.bin', 'rb') as f:
    report_data = f.read()

report = AttestationReport.unpack(report_data)

# Verify report (will auto-fetch certificates if needed)
try:
    verify_report(report, certs_dir='./certs/', verbose=True)
    print("Report verification successful!")
except Exception as e:
    print(f"Verification failed: {e}")
```

### Policy Validation

The toolkit supports validating attestation reports against security policies defined in JSON format. This allows you to enforce specific security requirements and check measurements are known good values.

#### Policy File Format

Policies are defined in JSON format with the following structure:

```json
{
  "metadata": {
    "name": "AMD SEV-SNP Security Policy",
    "version": "1.0",
    "description": "Example security policy for validating AMD SEV-SNP attestation reports"
  },
  "validation_rules": {
    "measurement": {
      "exact_match": "123456789abcdef..."
    },
    "version": {
      "min_value": 3
    },
    "policy": {
      "migrate_ma_allowed": false,
      "debug_allowed": false
    },
    "platform_info": {
      "tsme_enabled": true,
      "alias_check_complete": true
    },
    "current_tcb": {
      "bootloader": {
        "min_value": 9
      },
      "tee": {
        "min_value": 0
      },
      "snp": {
        "min_value": 15
      },
      "microcode": {
        "min_value": 72
      }
    }
  }
}
```

#### Policy Validation Rules

The following validation rule types are supported:

- **exact_match**: Field must exactly match the specified value. A non-boolean value given directly as the attribute value (e.g. `"vmpl": 0`) is shorthand for this rule.
- **min_value**: Field must be greater than or equal to the specified minimum
- **max_value**: Field must be less than or equal to the specified maximum
- **allow_list**: Field value must be in the list of allowed values
- **deny_list**: Field value must not be in the list of denied values
- **boolean**: Field must match the specified boolean value (true/false). This can be specified using the boolean value as the attribute value directly.

Byte fields (`measurement`, `host_data`, `report_data`, `id_key_digest`, `chip_id`, …) are written as hex strings in the policy, for `exact_match`, `allow_list` and `deny_list` alike. Case is ignored and an optional `0x` prefix is accepted. A value that is not valid hex fails the rule.

#### Using Policy Validation

Policy validation can be used programmatically:

```python
from sev_pytools import AttestationPolicy, AttestationReport

# Load policy from file
policy = AttestationPolicy(policy_file="policy.json")

# Load attestation report
report = AttestationReport.from_file("report.bin")

# Validate report against policy
try:
    policy.validate_report(report, verbose=True)
    print("Report passed all policy checks!")
except PolicyValidationError as e:
    print(f"Policy validation failed: {e}")
```

The `verify.py` script also supports policy validation when the `-q` or `--policy` flag is used with a policy file path:

```
python verify.py -f path/to/report.bin -c path/to/certs/directory -q path/to/policy.json [-v]
```

This will perform both cryptographic verification of the attestation report and validate it against the specified policy file.

## Certificate Management

### Built-in AMD Root Certificates

The AMD Root Key (ARK) and AMD SEV Signing Key (ASK) certificates for Milan,
Genoa (also used by Bergamo and Siena) and Turin are embedded as PEM constants,
one module per family: `sev_pytools/amd_certs/{milan,genoa,turin}.py`, each
exposing `ARK` and `ASK` (every family has its own self-signed ARK). They were
taken from `https://kdsintf.amd.com/vcek/v1/<Family>/cert_chain` and
cross-checked against the copies embedded in the `sev` Rust crate; the SHA-256
fingerprints are recorded in each module.

Consequences:

- Only the per-chip VCEK (and the CRL) is ever fetched from the KDS.
- **ARK/ASK are optional everywhere.** `load_certificates()`,
  `verify_certificate_chain*()` and `verify_attestation_report()` only need the
  VCEK; a missing ARK/ASK is filled from the built-ins (`complete_certificates()`).
  The family comes from the processor model / the report's CPUID when known;
  otherwise each built-in chain is tried and the one whose ASK actually signed the
  VCEK is used. Certificates you do provide (e.g. from a directory) are still used.
- Chain verification **pins the ARK**: whatever ARK is supplied (certs directory,
  KDS, hypervisor certificate table) must be byte-for-byte one of the built-in
  roots — for the report's processor family when the report carries CPUID
  information (version 3+). A self-signed look-alike is rejected. Pass
  `pin_ark=False` to `verify_certificate_chain()` to opt out.

```python
from sev_pytools import ProcType, builtin_ca, is_builtin_ark, verify_attestation_report

ca = builtin_ca(ProcType.GENOA)        # {"ark": ..., "ask": ...}
is_builtin_ark(some_cert, ProcType.TURIN)  # True only for the pinned Turin ARK

# Only the VCEK is needed; ARK/ASK come from the built-ins
verify_attestation_report(report, {"vcek": vcek}, crl, policy, report_data)
```

### Automatic Certificate Fetching

By default, the library automatically fetches from AMD's Key Distribution Service (KDS)
what is not built in or already present locally:

- Versioned Chip Endorsement Key (VCEK) Certificate
- Certificate Revocation List (CRL)

### Local Certificate Storage

For offline verification or to avoid network requests, certificates are stored locally:

```
certs/
├── ark.pem          # AMD Root Key (optional: built in)
├── ask.pem          # AMD SEV Signing Key (optional: built in)
├── crl.pem          # AMD CRL
└── vcek.pem         # Versioned Chip Endorsement Key
```

### Fetching Certificates

To fetch certificates from the AMD Key Distribution Service:

```
python fetch.py ca -p PROCESSOR -e ENCODING -d DIRECTORY [--endorser {vcek,vlek}]
python fetch.py vcek -p PROCESSOR -e ENCODING -d DIRECTORY -r REPORT_PATH
```
or if installed with pip use `sev-fetch ...`.

- `ca`: Fetch ARK and ASK certificates
- `vcek`: Fetch VCEK certificate
- `-p` or `--processor`: Processor model (e.g., milan, genoa) (default: genoa)
- `-e` or `--encoding`: Certificate encoding format (PEM or DER)
- `-d` or `--dir`: Directory to save the fetched certificates (default: `$SEV_PYTOOLS_CERTS_DIR` or `~/.cache/sev_pytools`)
- `--endorser`: Endorser type (vcek or vlek) for fetching VCEK or VLEK certificates
- `-r` or `--report`: Path to the attestation report file (required for fetching VCEK)

## Logging

SNP PyTools includes comprehensive logging support for both library usage and command-line tools. This helps with debugging, monitoring, and auditing.

### Command Line Logging

All command-line tools support logging flags.
Available logging options:
- `-v, --verbose`: Enable verbose logging (shows DEBUG level messages)
- `-q, --quiet`: Enable quiet mode (only WARNING and ERROR messages)
- `--log-file PATH`: Write logs to specified file in addition to console output

```bash
# Enable verbose logging (DEBUG level)
sev-verify -f report.bin --verbose

# Enable quiet mode (WARNING level and above)
sev-fetch ca --quiet

# Save logs to file
sev-print -f report.bin --log-file verification.log
```



### Library Logging

When using sev_pytools as a library, you can configure logging to suit your application:

```python
from sev_pytools import setup_library_logging, get_logger, AttestationReport

# Setup logging for library usage
logger = setup_library_logging(level="INFO", log_file="sev_operations.log")

# Use the logger
logger.info("Starting attestation report processing")

# Load and process a report - the library will automatically log key operations
with open("report.bin", "rb") as f:
    data = f.read()

report = AttestationReport.unpack(data)  # This will log parsing progress
logger.info("Successfully parsed attestation report")
```

## Requirements

## Installation

### Requirements

- Python 3.6+
- Dependencies (automatically installed):
  - `cryptography >= 39.0.0`
  - `requests >= 2.25.0`

### Install from Source

```bash
git clone https://github.com/TEE-Attestation/sev_pytools.git
cd sev_pytools
pip install .
```

### Uninstallation

```bash
pip uninstall sev_pytools
```

## Contributing

Contributions are welcome! Please follow the contribution guidelines in the [TAS repository](https://github.com/TEE-Attestation/tas/blob/main/CONTRIBUTING.md).

## Acknowledgments

This project is based on the AMD SEV-SNP specification and related documentation.
All the specifications used can be found here: [https://www.amd.com/en/developer/sev.html](https://www.amd.com/en/developer/sev.html)

The snpguest rust tool that can be used to generate the attestation report, and that models the verification process, can be found here: [https://github.com/virtee/snpguest/tree/main](https://github.com/virtee/snpguest/tree/main)

## License

MIT License - Copyright 2025 Hewlett Packard Enterprise Development LP.

See [LICENSE](LICENSE) file for details.