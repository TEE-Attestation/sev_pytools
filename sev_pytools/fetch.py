# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Certificate fetching utilities for AMD SEV-SNP attestation reports.

import argparse
import enum
import os

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .attestation_report import AttestationReport
from .sev_logging import get_logger, log_network_request, setup_cli_logging

logger = get_logger(__name__)

# Constants for AMD Key Distribution Service (KDS)
KDS_CERT_SITE = "https://kdsintf.amd.com"
KDS_VERSION = "v1"
KDS_CERT_CHAIN = "cert_chain"
KDS_CRL = "crl"

# Default certificate cache shared by all sev_pytools commands
CERTS_DIR_ENV = "SEV_PYTOOLS_CERTS_DIR"
CERTS_DIR_HELP = f"${CERTS_DIR_ENV} or ~/.cache/sev_pytools"


def default_certs_dir() -> str:
    """$SEV_PYTOOLS_CERTS_DIR, else $XDG_CACHE_HOME/sev_pytools, else ~/.cache/sev_pytools."""
    override = os.environ.get(CERTS_DIR_ENV)
    if override:
        return os.path.expanduser(override)
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return os.path.join(base, "sev_pytools")


# Enum classes for various certificate and processor types
class Endorsement(enum.Enum):
    VCEK = "VCEK"
    VLEK = "VLEK"


class ProcType(enum.Enum):
    TURIN = "Turin"
    MILAN = "Milan"
    GENOA = "Genoa"
    BERGAMO = "Bergamo"
    SIENA = "Siena"

    def to_kds_url(self):
        """
        to_kds_url
        Description: Convert processor type to KDS URL format
        Input: self (ProcType)
        Output: str (URL-friendly processor name)
        """
        if self in [ProcType.GENOA, ProcType.SIENA, ProcType.BERGAMO]:
            return ProcType.GENOA.value
        return self.value


class CertFormat(enum.Enum):
    PEM = "pem"
    DER = "der"


def create_retry_session(
    retries=5, backoff_factor=0.1, status_forcelist=(500, 502, 503, 504), timeout=5
):
    """
    create_retry_session
    Description: Create a requests session with retry logic
    Inputs:
        - retries: int (number of retries)
        - backoff_factor: float (backoff factor for retries)
        - status_forcelist: tuple (HTTP status codes to retry on)
        - timeout: int (default timeout for requests)
    Output: requests.Session object with retry logic
    """
    session = requests.Session()
    retries = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.timeout = timeout
    return session


def cpuid_to_processor_type(cpuid) -> ProcType:
    """
    cpuid_to_processor_type
    Description: Convert CPUID information to processor type
    Input: cpuid (Cpuid object from attestation report)
    Output: ProcType enum value
    """
    # AMD Zen architecture family mapping
    # Family 0x19 covers Milan and Genoa
    # Family 0x1A covers Turin
    if cpuid.family_id == 0x19:
        # Model ID determines the specific processor generation
        if cpuid.model_id in [0x00, 0x01, 0x08]:  # Milan
            return ProcType.MILAN
        elif cpuid.model_id in [0x10, 0x11, 0x18]:  # Genoa
            return ProcType.GENOA
        elif cpuid.model_id in [0xA0, 0xA1]:  # Bergamo
            return ProcType.BERGAMO
        elif cpuid.model_id in [0xB0, 0xB1]:  # Siena
            return ProcType.SIENA
    if cpuid.family_id == 0x1A:  # Turin
        return ProcType.TURIN

    raise ValueError(
        f"Unknown processor type: Family={cpuid.family_id}, Model={cpuid.model_id}, Stepping={cpuid.stepping}"
    )


def detect_processor_from_report(report: AttestationReport) -> ProcType:
    """
    detect_processor_from_report
    Description: Detect processor type from attestation report
    Input: report (AttestationReport object)
    Output: ProcType enum value
    """
    return cpuid_to_processor_type(report.cpuid)


def request_ca_kds(processor_model: ProcType, endorser: Endorsement):
    """
    request_ca_kds
    Description: Fetch CA certificates from AMD KDS
    Inputs:
        - processor_model: ProcType
        - endorser: Endorsement
    Output: List of x509.Certificate objects
    """
    url = f"{KDS_CERT_SITE}/{endorser.value.lower()}/{KDS_VERSION}/{processor_model.to_kds_url()}/{KDS_CERT_CHAIN}"

    logger.info(f"Fetching CA certificates from AMD KDS")
    logger.debug(f"URL: {url}")
    log_network_request(url, "GET")

    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    log_network_request(url, "GET", response.status_code)

    if response.status_code == 200:
        certs = x509.load_pem_x509_certificates(response.content)
        logger.info(f"Successfully fetched {len(certs)} CA certificates")
        return certs
    else:
        error_msg = f"Unable to fetch certificates: HTTP {response.status_code}"
        logger.error(error_msg)
        raise Exception(error_msg)


def write_cert(
    certs_dir, cert_type, cert, cert_format: CertFormat, endorser: Endorsement
):
    """
    write_cert
    Description: Write a certificate to a file
    Inputs:
        - certs_dir: str (directory to save the certificate)
        - cert_type: str (type of certificate, e.g., "ARK", "ASK")
        - cert: x509.Certificate
        - cert_format: CertFormat
        - endorser: Endorsement
    Output: None (writes certificate to file)
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)
        logger.debug(f"Created directory: {certs_dir}")

    filename = f"{cert_type.lower()}.{cert_format.value}"
    filepath = os.path.join(certs_dir, filename)

    if cert_format == CertFormat.PEM:
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    elif cert_format == CertFormat.DER:
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

    logger.info(f"Saved {cert_type} certificate to: {filepath}")
    logger.debug(f"Certificate format: {cert_format.value}")


def fetch_ca(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    endorser: Endorsement,
):
    """
    fetch_ca
    Description: Fetch and save CA certificates (ARK and ASK)
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save certificates)
        - endorser: Endorsement
    Output: None (saves certificates to files)
    """
    certificates = request_ca_kds(processor_model, endorser)

    ark_cert = certificates[1]
    ask_cert = certificates[0]

    write_cert(certs_dir, "ARK", ark_cert, encoding, endorser)
    write_cert(certs_dir, "ASK", ask_cert, encoding, endorser)


def request_vcek_kds(
    processor_model: ProcType,
    att_report_path: str = None,
    report: AttestationReport = None,
):
    """
    request_vcek_kds
    Description: Fetch VCEK certificate from AMD KDS
    Inputs:
        - processor_model: ProcType
        - att_report_path: str (path to attestation report file)
    Output: x509.Certificate
    """
    if report is None:
        if att_report_path is None:
            att_report_path = "report.bin"
        try:
            with open(att_report_path, "rb") as file:
                binary_data = file.read()

            if not binary_data:
                raise ValueError(f"Attestation report file is empty: {att_report_path}")

            report = AttestationReport.unpack(binary_data)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Attestation report file not found: {att_report_path}"
            )
        except PermissionError:
            raise PermissionError(
                f"Permission denied reading attestation report: {att_report_path}"
            )
        except Exception as e:
            raise ValueError(
                f"Error reading or parsing attestation report from {att_report_path}: {str(e)}"
            )

    hw_id = report.get_hwid()
    url = (
        f"{KDS_CERT_SITE}/vcek/{KDS_VERSION}/{processor_model.to_kds_url()}/"
        f"{hw_id}?blSPL={report.reported_tcb.bootloader:02}&"
        f"teeSPL={report.reported_tcb.tee:02}&"
        f"snpSPL={report.reported_tcb.snp:02}&"
        f"ucodeSPL={report.reported_tcb.microcode:02}"
    )

    logger.info("Fetching VCEK certificate from AMD KDS")
    logger.debug(f"URL: {url}")
    log_network_request(url, "GET")

    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    log_network_request(url, "GET", response.status_code)

    if response.status_code == 200:
        try:
            # Try to load as PEM
            cert = x509.load_pem_x509_certificate(response.content)
            logger.debug("Successfully loaded VCEK certificate as PEM")
        except ValueError:
            try:
                # If PEM fails, try to load as DER
                cert = x509.load_der_x509_certificate(response.content)
                logger.debug("Successfully loaded VCEK certificate as DER")
            except ValueError:
                logger.error("Unable to load certificate in either DER or PEM format")
                raise ValueError(
                    "Unable to load certificate. It must be in DER or PEM format."
                )
        logger.info("Successfully fetched VCEK certificate")
        return cert
    else:
        error_msg = f"Unable to fetch VCEK: HTTP {response.status_code}"
        logger.error(error_msg)
        raise Exception(error_msg)


def fetch_vcek(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    att_report_path: str,
):
    """
    fetch_vcek
    Description: Fetch and save VCEK certificate
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save certificate)
        - att_report_path: str (path to attestation report file)
    Output: None (saves VCEK certificate to file)
    """
    vcek = request_vcek_kds(processor_model, att_report_path)
    write_cert(certs_dir, "VCEK", vcek, encoding, Endorsement.VCEK)


def request_crl_kds(processor_model: ProcType, endorser: Endorsement):
    """
    request_crl_kds
    Description: Fetch CRL from AMD KDS
    Inputs:
        - processor_model: ProcType
        - endorser: Endorsement
    Output: x509.CertificateRevocationList
    """
    url = f"{KDS_CERT_SITE}/{endorser.value.lower()}/{KDS_VERSION}/{processor_model.to_kds_url()}/{KDS_CRL}"

    logger.info("Fetching CRL from AMD KDS")
    logger.debug(f"URL: {url}")
    log_network_request(url, "GET")

    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    log_network_request(url, "GET", response.status_code)

    if response.status_code == 200:
        crl = x509.load_der_x509_crl(response.content)
        logger.info("Successfully fetched CRL")
        return crl
    else:
        error_msg = f"Unable to fetch CRL: HTTP {response.status_code}"
        logger.error(error_msg)
        raise Exception(error_msg)


def fetch_crl(
    encoding: CertFormat,
    processor_model: ProcType,
    certs_dir: str,
    endorser: Endorsement,
):
    """
    fetch_crl
    Description: Fetch and save CRL
    Inputs:
        - encoding: CertFormat
        - processor_model: ProcType
        - certs_dir: str (directory to save CRL)
        - endorser: Endorsement
    Output: None (saves CRL to file)
    """
    crl = request_crl_kds(processor_model, endorser)
    write_cert(certs_dir, "CRL", crl, encoding, endorser)


def main():
    """
    main
    Description: Parse command-line arguments and execute appropriate certificate fetching function
    Input: None (uses command-line arguments)
    Arguments:
        -e, --encoding: Certificate encoding (choices: pem, der; default: pem)
        -p, --processor: Processor model (choices: milan, genoa, bergamo, siena; default: genoa)
        -d, --dir: Directory to save certificates (default: current directory)
        -v, --verbose: Enable verbose logging (flag)
        -q, --quiet: Enable quiet mode (flag)
        --log-file: Path to log file (optional)
        ca: Subcommand to fetch certificate authority (ARK & ASK)
            --endorser: Endorsement type for CA (choices: vcek, vlek; default: vcek)
        crl: Subcommand to fetch CRL
            --endorser: Endorsement type for CRL (choices: vcek, vlek; default: vcek)
        vcek: Subcommand to fetch VCEK
            -r, --report: Path to the attestation report (required for VCEK)
    Output: None (fetches and saves certificates based on user input)
    Examples:
        python fetch.py ca
        python fetch.py ca -p milan --verbose
        python fetch.py ca -p genoa -e der -d /path/to/certs
        python fetch.py ca -p bergamo -e der -d /path/to/certs --endorser vlek
        python fetch.py crl -p genoa -d /path/to/certs
        python fetch.py vcek -p siena -r report.bin
        python fetch.py vcek -r report.bin
    """
    parser = argparse.ArgumentParser(description="Fetch AMD certificates")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-e",
        "--encoding",
        type=str,
        choices=["pem", "der"],
        default="pem",
        help="Certificate encoding (default: pem)",
    )
    common_parser.add_argument(
        "-p",
        "--processor",
        type=str,
        choices=["milan", "genoa", "bergamo", "siena"],
        default="genoa",
        help="Processor model",
    )
    common_parser.add_argument(
        "-d",
        "--dir",
        type=str,
        default=None,
        help=f"Directory to save certificates (default: {CERTS_DIR_HELP})",
    )
    common_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging",
    )
    common_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Enable quiet mode (warnings and errors only)",
    )
    common_parser.add_argument(
        "--log-file", type=str, help="Path to log file (optional)"
    )

    # CA subcommand
    ca_parser = subparsers.add_parser(
        "ca",
        parents=[common_parser],
        help="Fetch the certificate authority (ARK & ASK) from the KDS",
    )
    ca_parser.add_argument(
        "--endorser",
        type=str,
        choices=["vcek", "vlek"],
        default="vcek",
        help="Endorsement type (default: vcek)",
    )

    # CRL subcommand
    crl_parser = subparsers.add_parser(
        "crl",
        parents=[common_parser],
        help="Fetch the CRL from the KDS",
    )
    crl_parser.add_argument(
        "--endorser",
        type=str,
        choices=["vcek", "vlek"],
        default="vcek",
        help="Endorsement type (default: vcek)",
    )

    # VCEK subcommand
    vcek_parser = subparsers.add_parser(
        "vcek", parents=[common_parser], help="Fetch the VCEK from the KDS"
    )
    vcek_parser.add_argument(
        "-r", "--report", type=str, required=True, help="Path to the attestation report"
    )

    args = parser.parse_args()

    # Setup logging
    logger = setup_cli_logging(
        verbose=args.verbose, quiet=args.quiet, log_file=args.log_file
    )

    try:
        # Convert string arguments to enum types
        encoding = CertFormat[args.encoding.upper()]
        processor_model = ProcType[args.processor.upper()]
        if args.dir is None:
            args.dir = default_certs_dir()

        logger.info(
            f"Fetching {args.command} certificates for processor: {processor_model.value}"
        )
        logger.debug(f"Encoding: {encoding.value}, Directory: {args.dir}")

        if args.command == "ca":
            endorser = Endorsement[args.endorser.upper()]
            logger.info(f"Fetching CA certificates with endorser: {endorser.value}")
            fetch_ca(encoding, processor_model, args.dir, endorser)
        elif args.command == "crl":
            endorser = Endorsement[args.endorser.upper()]
            logger.info(f"Fetching CRL with endorser: {endorser.value}")
            fetch_crl(encoding, processor_model, args.dir, endorser)
        elif args.command == "vcek":
            logger.info(f"Fetching VCEK using report: {args.report}")
            fetch_vcek(encoding, processor_model, args.dir, args.report)

        logger.info("Certificate fetching completed successfully")
        return 0

    except KeyError as e:
        logger.error(f"Invalid argument value: {e}")
        return 1
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error fetching certificates: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        return 1


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
