# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# sev_pytools - Python tools for AMD SEV attestation.

"""
sev_pytools - Python tools for AMD SEV attestation

This package provides tools for working with AMD SEV attestation reports,
including parsing, verification, policy validation, and certificate management.
"""

# Core attestation report components
from .attestation_report import AttestationReport, Cpuid, KeyInfo, TcbVersion, Version

# Built-in AMD certificate authorities (ARK/ASK per processor family)
from .builtin_certs import (
    builtin_ark,
    builtin_ask,
    builtin_ca,
    builtin_chains,
    builtin_family_of_ark,
    is_builtin_ark,
)

# Certificate and verification functions
from .certs import (
    cert_verify_report,
    cert_verify_report_components,
    check_certificate_against_crl,
    complete_certificates,
    load_certificates,
    load_crl,
    log_all_certs,
    log_certificate_fields,
    log_crl_fields,
    verify_certificate,
    verify_crl,
)

# Fetching certificates and CRLs
from .fetch import (
    CertFormat,
    Endorsement,
    ProcType,
    cpuid_to_processor_type,
    detect_processor_from_report,
    fetch_ca,
    fetch_crl,
    fetch_vcek,
)
from .guest_policy import GuestPolicy
from .platform_info import PlatformInfo

# Policy validation
from .policy import (
    AttestationPolicy,
    PolicyValidationError,
    validate_report_with_policy,
)

# Logging utilities
from .sev_logging import (
    get_logger,
    log_certificate_info,
    log_network_request,
    log_policy_validation,
    log_section_header,
    log_subsection_header,
    log_verification_step,
    setup_cli_logging,
    setup_library_logging,
    setup_logging,
)
from .signature import Signature

# High-level verification functions
from .verify import (
    cert_verify_attestation_report,
    policy_verify_attestation_report,
    verify_attestation_bytes,
    verify_attestation_report,
    verify_certificate_chain,
    verify_certificate_chain_with_crl,
)

__version__ = "0.6.0"
__author__ = "Isaac Matthews"

__all__ = [
    # Core classes
    "AttestationReport",
    "TcbVersion",
    "Cpuid",
    "GuestPolicy",
    "PlatformInfo",
    "Signature",
    # Built-in AMD CA
    "builtin_ark",
    "builtin_ask",
    "builtin_ca",
    "builtin_chains",
    "builtin_family_of_ark",
    "is_builtin_ark",
    # Certificate functions
    "check_certificate_against_crl",
    "complete_certificates",
    "load_certificates",
    "load_crl",
    "log_all_certs",
    "log_certificate_fields",
    "log_crl_fields",
    "verify_certificate",
    "verify_crl",
    "cert_verify_report",
    "cert_verify_report_components",
    # Policy validation
    "AttestationPolicy",
    "PolicyValidationError",
    "validate_report_with_policy",
    # Fetching
    "CertFormat",
    "Endorsement",
    "ProcType",
    "cpuid_to_processor_type",
    "detect_processor_from_report",
    "fetch_ca",
    "fetch_crl",
    "fetch_vcek",
    # High-level verification
    "verify_attestation_bytes",
    "verify_attestation_report",
    "verify_certificate_chain",
    "verify_certificate_chain_with_crl",
    "cert_verify_attestation_report",
    "policy_verify_attestation_report",
    # Logging utilities
    "get_logger",
    "setup_cli_logging",
    "setup_library_logging",
    "setup_logging",
    "log_verification_step",
    "log_certificate_info",
    "log_policy_validation",
    "log_network_request",
]
