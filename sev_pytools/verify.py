# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Command-line utility for verifying AMD SEV-SNP attestation reports.

import argparse
import json
import os
import struct

from cryptography import x509

from .attestation_report import AttestationReport
from .builtin_certs import builtin_family_of_ark, is_builtin_ark
from .certs import (
    cert_verify_report,
    check_certificate_against_crl,
    complete_certificates,
    load_certificates,
    load_crl,
    log_all_certs,
    log_crl_fields,
    verify_certificate,
    verify_crl,
)
from .fetch import (
    CertFormat,
    Endorsement,
    ProcType,
    cpuid_to_processor_type,
    fetch_crl,
    request_vcek_kds,
    write_cert,
)
from .policy import (
    AttestationPolicy,
    PolicyValidationError,
    validate_report_with_policy,
)
from .sev_logging import (
    get_logger,
    log_certificate_info,
    log_policy_validation,
    log_section_header,
    log_subsection_header,
    log_verification_step,
    setup_cli_logging,
)

logger = get_logger(__name__)


def verify_certificate_chain(certificates, processor_model=None, pin_ark=True):
    """
    Verify the SEV-SNP certificate chain (ARK -> ASK -> VCEK).

    Args:
        certificates: Dictionary containing 'vcek' and optionally 'ark' and 'ask';
            a missing ARK/ASK is taken from the built-in AMD certificates
        processor_model: ProcType or str; selects the built-in chain and pins the
            ARK to that family's root. If None, the chain is found by trying each
            built-in family and the ARK must match one of the built-in roots.
        pin_ark: Set False to accept an ARK that is not a built-in AMD root

    Returns:
        bool: True if certificate chain is valid

    Raises:
        ValueError: If any certificate verification fails
    """
    logger.debug("Starting certificate chain verification")
    certificates = complete_certificates(certificates, processor_model)

    # Check that the ARK is a pinned AMD root (a self-signature alone proves nothing)
    ark_cert = certificates["ark"]
    if pin_ark:
        if not is_builtin_ark(ark_cert, processor_model):
            expected = (
                processor_model if processor_model is not None else "any known family"
            )
            raise ValueError(
                f"The ARK is not the built-in AMD root certificate ({expected})."
            )
        log_verification_step(
            f"ARK matches built-in AMD root ({builtin_family_of_ark(ark_cert)})", "PASS"
        )

    # Check if the ARK certificate is self-signed
    logger.debug("Verifying ARK self-signature")
    if not verify_certificate(ark_cert, ark_cert.public_key()):
        raise ValueError("The ARK is not self-signed.")
    log_verification_step("ARK self-signature", "PASS")

    # Check that the ASK is signed by the ARK
    ask_cert = certificates["ask"]
    logger.debug("Verifying ASK signature by ARK")
    if not verify_certificate(ask_cert, ark_cert.public_key()):
        raise ValueError("The ASK is not signed by the ARK.")
    log_verification_step("ASK signature by ARK", "PASS")

    # Check that the VCEK is signed by the ASK
    vcek_cert = certificates["vcek"]
    logger.debug("Verifying VCEK signature by ASK")
    if not verify_certificate(vcek_cert, ask_cert.public_key()):
        raise ValueError("The VCEK is not signed by the ASK.")
    log_verification_step("VCEK signature by ASK", "PASS")
    log_verification_step("Certificate chain verification", "PASS")

    return True


def verify_certificate_chain_with_crl(certificates, crl=None, processor_model=None):
    """
    verify_certificate_chain_with_crl
    Description: Verify the SEV-SNP certificate chain including CRL checks
    Inputs:
        certificates: Dictionary containing 'vcek' and optionally 'ark' and 'ask'
                      (missing ones come from the built-in AMD certificates)
        crl: x509.CertificateRevocationList object (optional)
        processor_model: ProcType or str used to select/pin the chain (optional)
    Output: bool: True if certificate chain is valid and no certificates are revoked
    """
    certificates = complete_certificates(certificates, processor_model)

    # Verify the basic certificate chain
    verify_certificate_chain(certificates, processor_model)

    # If CRL is provided, check each certificate against it
    if crl is not None:
        # Check that the CRL is signed by the ARK
        ark_cert = certificates["ark"]
        if not verify_crl(crl, ark_cert.public_key()):
            raise ValueError("The CRL is not signed by the ARK.")
        log_verification_step("CRL signature by ARK", "PASS")
        log_subsection_header("Checking ASK Against CRL")

        # Check ASK certificate against CRL
        ask_cert = certificates["ask"]
        if not check_certificate_against_crl(ask_cert, crl):
            raise ValueError("ASK certificate is revoked according to CRL.")
        log_verification_step("ASK certificate has not been revoked.", "OK")
    else:
        logger.info("No CRL provided")
        return False

    return True


def verify_attestation_bytes(
    report_bytes,
    certificates_path=None,
    certificates=None,
    crl=None,
    processor_model="genoa",
    policy_path=None,
):
    """
    Verify an SEV-SNP attestation report against certificate chain.

    Args:
        report_bytes: Binary attestation report data
        certificates_path: Path to certificates directory (if certificates not provided).
            Only the VCEK (and CRL) need to be there; ARK/ASK default to the built-ins
        certificates: Dictionary of certificates (if already loaded); only 'vcek' is required
        crl: x509.CertificateRevocationList (if already loaded)
        processor_model: Processor model for fetching certificates (default: "genoa");
            only used when the report does not carry CPUID information
        policy_path: Path to the policy file (if not provided, no policy validation will be performed)

    Returns:
        tuple: (report object, certificates dict, report data hex string)

    Raises:
        ValueError: For verification failures
        FileNotFoundError: If certificates cannot be loaded
    """
    report = AttestationReport.unpack(report_bytes)

    # Family for KDS URLs: from the report when it carries CPUID, else the caller's hint.
    # The built-in chain is only pre-selected when the report says; otherwise each is tried.
    proc_type = ProcType[processor_model.upper()]
    chain_model = None
    if report.supports_cpuid:
        proc_type = chain_model = cpuid_to_processor_type(report.cpuid)

    # Load certificates if not provided
    if certificates is None:
        if certificates_path is None:
            certificates_path = "ca"

        # Create certificates directory if it doesn't exist
        if not os.path.exists(certificates_path):
            logger.info(f"Creating certificates directory: {certificates_path}")
            os.makedirs(certificates_path, exist_ok=True)

        # ARK/ASK come from the built-in AMD certificates; only the VCEK is per-chip
        try:
            certificates = load_certificates(certificates_path, chain_model)
        except (ValueError, FileNotFoundError):
            logger.info("VCEK not found locally, fetching from AMD KDS...")
            vcek = request_vcek_kds(proc_type, report=report)
            write_cert(
                certificates_path, "VCEK", vcek, CertFormat.PEM, Endorsement.VCEK
            )
            certificates = load_certificates(certificates_path, chain_model)
            logger.info("VCEK successfully fetched and loaded.")

    # Load CRL if not provided
    if crl is None:
        try:
            crl = load_crl(certificates_path)
        except (ValueError, FileNotFoundError):
            logger.info(f"CRL not found, fetching from AMD KDS...")

            # Fetch CRL
            fetch_crl(CertFormat.PEM, proc_type, certificates_path, Endorsement.VCEK)

            # Now try loading CRL again
            crl = load_crl(certificates_path)
            logger.info("CRL successfully fetched and loaded.")

    # If policy validation is required, validate the report against the policy
    if policy_path:
        try:
            policy = AttestationPolicy(policy_file=policy_path)
        except FileNotFoundError:
            raise ValueError(f"Policy file not found: {policy_path}")
        verify_attestation_report(
            report=report,
            certificates=certificates,
            crl=crl,
            policy=policy,
        )
    else:
        cert_verify_attestation_report(
            report=report,
            certificates=certificates,
            crl=crl,
        )

    return report, certificates, report.report_data.hex()


def cert_verify_attestation_report(
    report: AttestationReport,
    certificates: dict,
    crl: x509.CertificateRevocationList,
) -> bool:
    """
    Verify an SEV-SNP attestation report against a certificate chain and CRL.
    """
    log_section_header("CERTIFICATE VERIFICATION")

    log_subsection_header("Verifying Certificate Chain")
    # Pin the ARK to the report's processor family when the report tells us (v3+)
    processor_model = None
    if report.supports_cpuid:
        try:
            processor_model = cpuid_to_processor_type(report.cpuid)
        except ValueError as e:
            logger.warning(f"{e}; pinning ARK against all built-in AMD roots")
    verify_certificate_chain_with_crl(certificates, crl, processor_model)

    # Check that the report is signed by the VCEK
    log_subsection_header("Verifying Attestation Report Signature")

    vcek_cert = certificates["vcek"]
    if not cert_verify_report(report, vcek_cert):
        raise ValueError(
            "The attestation report failed verification against the VCEK certificate."
        )

    logger.info("✓ Report verified successfully against the VCEK certificate.")
    logger.info("All certificate checks passed successfully.")
    return True


def policy_verify_attestation_report(
    report: AttestationReport,
    policy: AttestationPolicy,
    report_data: bytes = None,
) -> bool:
    """
    Verify an SEV-SNP attestation report against a policy.
    """
    log_section_header("POLICY VALIDATION")

    logger.info("Starting policy validation")

    # Validate report against policy
    if not policy.validate_report(report, report_data):
        error_msg = "Attestation report failed validation against policy"
        logger.error(error_msg)
        raise ValueError(error_msg)

    log_verification_step("Report validation against policy", "PASS")
    logger.info("Policy validation completed successfully")
    return True


def verify_attestation_report(
    report: AttestationReport,
    certificates: dict,
    crl: x509.CertificateRevocationList,
    policy: AttestationPolicy,
    report_data: bytes = None,
) -> bool:
    """
    Verify an SEV_SNP attestation report against certificates, crl, and policy.
    """
    cert_verify_attestation_report(report, certificates, crl)
    policy_verify_attestation_report(report, policy, report_data)
    return True


def main():
    """
    main
    Description: Parse command-line arguments, load and verify the attestation report and certificate chain
    Input: None (uses command-line arguments)
    Arguments:
        -f, --file: Path to the report file (default: report.bin)
        -v, --verbose: Enable verbose mode (flag, default: False)
        --quiet: Enable quiet mode (flag, default: False)
        --log-file: Path to log file (optional)
        -c, --certs: Path to the certs directory (default: ca)
        -r, --reportdata: Print report data at the end of successful verification (flag, default: False)
        -p, --processor: Processor model for certificate fetching, only used if certs are not provided (choices: milan, genoa, bergamo, siena; default: genoa)
        -q, --policy: Path to the policy file (default: example_policy.json)
    Output: None (prints verification results to console and exits with status code)
    Examples:
        python verify.py
        python verify.py -f custom_report.bin -c /path/to/certs
        python verify.py -f custom_report.bin -c /path/to/certs --verbose
    """
    parser = argparse.ArgumentParser(description="Verify attestation report")
    parser.add_argument(
        "-f",
        "--file",
        default="report.bin",
        help="Path to the report file (default: report.bin)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose mode",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Enable quiet mode (warnings and errors only)",
    )
    parser.add_argument("--log-file", type=str, help="Path to log file (optional)")
    parser.add_argument(
        "-c",
        "--certs",
        default="ca",
        help="Path to the certs directory (default: ca). Holds the VCEK and CRL; "
        "ARK/ASK are optional and default to the built-in AMD certificates",
    )
    parser.add_argument(
        "-r",
        "--reportdata",
        action="store_true",
        default=False,
        help="Print report data at the end of successful verification",
    )
    parser.add_argument(
        "-p",
        "--processor",
        default="genoa",
        choices=["milan", "genoa", "bergamo", "siena"],
        help="Processor model for certificate fetching (default: genoa)",
    )
    parser.add_argument(
        "-q",
        "--policy",
        default=None,
        help="Path to the policy file (eg. example_policy.json). If not provided, no policy validation will be performed.",
    )
    args = parser.parse_args()

    # Setup logging (use verbose from command line for both verbose output and logging)
    logger = setup_cli_logging(
        verbose=args.verbose, quiet=args.quiet, log_file=args.log_file
    )

    try:
        logger.info(f"Starting verification of attestation report: {args.file}")
        logger.debug(f"Using certificates from: {args.certs}")
        logger.debug(f"Processor model: {args.processor}")
        if args.policy:
            logger.debug(f"Policy file: {args.policy}")

        with open(args.file, "rb") as file:
            report_bytes = file.read()

        logger.debug(f"Read {len(report_bytes)} bytes from report file")

        report, certificates, report_data = verify_attestation_bytes(
            report_bytes=report_bytes,
            certificates_path=args.certs,
            processor_model=args.processor,
            policy_path=args.policy,
        )

        # Print report details if verbose mode is enabled
        if args.verbose:
            report.log_details()

        # Print certificate and CRL details if verbose mode is enabled
        if args.verbose and certificates:
            log_subsection_header("Loaded Certificates:")
            log_all_certs(certificates)

        if args.verbose:
            # Load CRL for display
            try:
                from .certs import load_crl

                crl = load_crl(args.certs)
                log_subsection_header("Loaded CRL:")
                log_crl_fields(crl)
            except (ValueError, FileNotFoundError):
                logger.debug("CRL not available for display")

        if args.policy:
            logger.info("VERIFICATION COMPLETE")
            logger.info(
                "SUCCESS: Attestation report successfully verified against certificates and policy."
            )
            logger.info(
                "Attestation report verification completed successfully (with policy)"
            )
        else:
            logger.info("VERIFICATION COMPLETE")
            logger.info(
                "SUCCESS: Attestation report successfully verified against certificates."
            )
            logger.info(
                "Attestation report verification completed successfully (without policy)"
            )

        if args.reportdata:
            logger.info(f"Report Data (hex): \n{report_data}")

        return 0  # Success exit code

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except PolicyValidationError as e:
        logger.error(f"Policy validation failed: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return 1
    except (ValueError, OSError) as e:
        logger.error(f"Verification error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        return 1


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
