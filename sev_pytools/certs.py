# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Certificate management and verification utilities for AMD SEV-SNP attestation.

import binascii
import datetime
import os
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, utils
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ObjectIdentifier

from .builtin_certs import builtin_ca, builtin_chains, builtin_family_of_ark
from .sev_logging import get_logger

logger = get_logger(__name__)


# There are taken from SEV-SNP Platform Attestation Using VirTEE/SEV
# https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf
class SnpOid(Enum):
    BootLoader = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.1")
    Tee = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.2")
    Snp = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.3")
    Ucode = ObjectIdentifier("1.3.6.1.4.1.3704.1.3.8")
    HwId = ObjectIdentifier("1.3.6.1.4.1.3704.1.4")

    def __str__(self):
        return self.value.dotted_string


def load_certificates(cert_dir, processor_model=None):
    """
    load_certificates
    Description: Load certificates from a directory. Only the VCEK is required:
                 a missing ARK and/or ASK is taken from the built-in AMD
                 certificates (see complete_certificates).
    Inputs:
        cert_dir (str): Path to the directory containing certificates
        processor_model (ProcType or str, optional): Processor family of the built-in CA
    Output: dict: Dictionary of loaded certificates
    """
    certs = {}
    required_certs = ["ark", "ask", "vcek"]

    for filename in os.listdir(cert_dir):
        cert_type = next(
            (ct for ct in required_certs if filename.startswith(f"{ct}.")), None
        )
        if cert_type:
            if cert_type in certs:
                raise ValueError(
                    f"Multiple {cert_type.upper()} certificates found. There should be exactly one."
                )

            with open(os.path.join(cert_dir, filename), "rb") as cert_file:
                cert_data = cert_file.read()
                try:
                    # Try to load as DER
                    cert = x509.load_der_x509_certificate(cert_data)
                except ValueError:
                    try:
                        # If DER fails, try to load as PEM
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except ValueError:
                        raise ValueError(
                            f"Unable to load certificate {filename}. It must be in DER or PEM format."
                        )

                certs[cert_type] = cert

    if "vcek" not in certs:
        raise ValueError("Missing required certificates: VCEK")
    return complete_certificates(certs, processor_model)


def complete_certificates(certificates, processor_model=None):
    """
    complete_certificates
    Description: Fill a missing ARK and/or ASK from the built-in AMD certificates.
                 The chain is selected by processor model when given; otherwise
                 each built-in chain is tried and the one whose ASK signed the
                 VCEK is used. Certificates that are present are kept as given
                 (the chain verification still pins the ARK).
    Inputs:
        certificates (dict): Must contain "vcek"; "ark" and "ask" are optional
        processor_model (ProcType or str, optional): Processor family of the chain
    Output: dict: New dictionary containing "ark", "ask" and "vcek"
    Raises: ValueError if the VCEK is missing or was not issued by a built-in ASK
    """
    missing = {"ark", "ask"} - set(certificates)
    if not missing:
        return dict(certificates)
    if "vcek" not in certificates:
        raise ValueError("Missing required certificates: VCEK")

    if processor_model is not None:
        ca = builtin_ca(processor_model)
    else:
        ca = _builtin_ca_that_issued(certificates["vcek"])
    family = builtin_family_of_ark(ca["ark"])

    completed = dict(certificates)
    for cert_type in sorted(missing):
        logger.info(
            f"{cert_type.upper()} not provided, using built-in AMD {family} certificate"
        )
        completed[cert_type] = ca[cert_type]
    return completed


def _builtin_ca_that_issued(vcek):
    """Try each built-in chain and return the one whose ASK signed the VCEK."""
    chains = builtin_chains()
    for family, ca in chains.items():
        if _is_signed_by(vcek, ca["ask"]):
            logger.info(f"VCEK was issued by the built-in AMD {family} ASK")
            return ca
    raise ValueError(
        f"The VCEK (issuer: {vcek.issuer.rfc4514_string()}) was not issued by any "
        f"built-in AMD ASK ({', '.join(chains)})."
    )


def _is_signed_by(cert, issuer):
    # Quiet variant of verify_certificate: failures are expected while probing chains.
    try:
        issuer.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding=cert.signature_algorithm_parameters,
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception:
        return False
    return True


def load_crl(crl_dir):
    """
    load_crl
    Description: Load a Certificate Revocation List (CRL) from a file
    Input: crl_dir (str): Path to the directory containing the CRL file
    Output: x509.CertificateRevocationList: Loaded CRL object
    """
    crl_files = [f for f in os.listdir(crl_dir) if f.startswith("crl")]

    if not crl_files:
        raise ValueError("No CRL file found in the specified directory")

    if len(crl_files) > 1:
        raise ValueError(
            f"Multiple CRL files found: {crl_files}. There should be exactly one."
        )

    with open(os.path.join(crl_dir, crl_files[0]), "rb") as crl_file:
        crl_data = crl_file.read()
        try:
            return x509.load_der_x509_crl(crl_data)
        except ValueError:
            try:
                return x509.load_pem_x509_crl(crl_data)
            except ValueError:
                raise ValueError("Unable to load CRL. It must be in DER or PEM format.")


def log_all_certs(certs):
    """
    log_all_certs
    Description: Log fields of all certificates in the given dictionary
    Input: certs (dict): Dictionary of certificates
    Output: None
    """
    for cert_type, cert in certs.items():
        logger.info(f"\n{cert_type.upper()} Certificate Fields:")
        log_certificate_fields(cert)


def get_public_key_algorithm(public_key):
    """
    get_public_key_algorithm
    Description: Determine the algorithm of the given public key
    Input: public_key: A public key object
    Output: str: Name of the public key algorithm
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECC (curve: {public_key.curve.name})"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    else:
        return "Unknown"


def get_extension_value(cert, oid):
    """
    get_extension_value
    Description: Get the value of a specific extension from a certificate
    Inputs:
        cert: x509.Certificate object
        oid: ObjectIdentifier of the extension
    Output: Value of the extension (various types possible)
    """
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
        value = ext.value
        if isinstance(value, x509.SubjectAlternativeName):
            return ", ".join(str(name) for name in value)
        elif isinstance(value, x509.KeyUsage):
            return repr(value)
        elif isinstance(value, x509.ExtendedKeyUsage):
            return ", ".join(str(usage) for usage in value)
        elif oid in [
            SnpOid.BootLoader.value,
            SnpOid.Tee.value,
            SnpOid.Snp.value,
            SnpOid.Ucode.value,
        ]:
            return int.from_bytes(value.value[2:], byteorder="big")
        elif oid == SnpOid.HwId.value:
            return binascii.hexlify(value.value).decode("ascii")
        else:
            return f"Unknown format: {binascii.hexlify(value.value).decode('ascii')}"
    except ExtensionNotFound:
        return "Not present"


def log_certificate_fields(cert):
    """
    log_certificate_fields
    Description: Log all relevant fields of a certificate
    Input: cert: x509.Certificate object
    Output: None
    """
    logger.info(f"Subject: {cert.subject.rfc4514_string()}")
    logger.info(f"Issuer: {cert.issuer.rfc4514_string()}")
    logger.info(f"Version: {cert.version}")
    logger.info(f"Serial Number: {cert.serial_number}")
    logger.info(f"Not Valid Before: {cert.not_valid_before_utc}")
    logger.info(f"Not Valid After: {cert.not_valid_after_utc}")
    logger.info(
        f"Subject Alternative Names: {get_extension_value(cert, x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)}"
    )
    logger.info(f"Key Usage: {get_extension_value(cert, x509.ExtensionOID.KEY_USAGE)}")
    logger.info(
        f"Extended Key Usage: {get_extension_value(cert, x509.ExtensionOID.EXTENDED_KEY_USAGE)}"
    )
    logger.info(f"Public Key Algorithm: {get_public_key_algorithm(cert.public_key())}")

    # Log SNP-specific extensions
    for snp_oid in SnpOid:
        value = get_extension_value(cert, snp_oid.value)
        if isinstance(value, int):
            logger.info(f"{snp_oid.name}: {value}")
        elif isinstance(value, str):
            logger.info(f"{snp_oid.name}: {value}")
        else:
            logger.info(f"{snp_oid.name}: Unknown format")


def log_crl_fields(crl):
    """
    log_crl_fields
    Description: Log information about a Certificate Revocation List
    Inputs:
        crl: x509.CertificateRevocationList object
    Output: None
    """
    logger.info(f"  Issuer: {crl.issuer.rfc4514_string()}")
    logger.info(f"  Last Update: {crl.last_update_utc}")
    logger.info(f"  Next Update: {crl.next_update_utc}")

    revoked_count = len(list(crl))
    logger.info(f"  Revoked Certificates: {revoked_count}")

    if revoked_count > 0:
        logger.info("  Revoked Certificate Details:")
        for i, revoked_cert in enumerate(crl):
            if i >= 10:  # Limit output for readability
                logger.info(f"    ... and {revoked_count - 10} more")
                break
            logger.info(
                f"    Serial: {revoked_cert.serial_number}, Revoked: {revoked_cert.revocation_date_utc}"
            )


def verify_certificate(cert, key):
    """
    verify_certificate
    Description: Verify a certificate's signature using a public key
    Inputs:
        cert: x509.Certificate object to verify
        key: Public key to use for verification
    Output: bool: True if verification succeeds, False otherwise
    """
    try:
        key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding=cert.signature_algorithm_parameters,
            algorithm=cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        logger.error("Invalid certificate signature.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying certificate: {str(e)}")
        return False
    return True


def verify_crl(crl, key):
    """
    verify_crl
    Description: Verify a certificate revocation list's signature using a public key
    Inputs:
        crl: x509.CRL object to verify
        key: Public key to use for verification
    Output: bool: True if verification succeeds, False otherwise
    """
    try:
        key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding=crl.signature_algorithm_parameters,
            # Manually specify the hash algorithm as currently it does not get recognized
            # algorithm=crl.signature_hash_algorithm,
            algorithm=hashes.SHA384(),
        )
    except InvalidSignature:
        logger.error("Invalid CRL signature.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying CRL: {str(e)}")
        return False
    return True


def cert_verify_report_components(report, cert):
    """
    cert_verify_report_components
    Description: Verify components of an attestation report against a certificate
    Inputs:
        report: Attestation report object
        cert: x509.Certificate object (VCEK)
    Output: bool: True if all components match, False otherwise
    """
    # Check TCB components
    tcb_components = [
        ("BootLoader", SnpOid.BootLoader),
        ("TEE", SnpOid.Tee),
        ("SNP", SnpOid.Snp),
        ("Microcode", SnpOid.Ucode),
    ]

    for component_name, oid in tcb_components:
        cert_value = get_extension_value(cert, oid.value)
        report_value = getattr(report.reported_tcb, component_name.lower())

        if cert_value == report_value:
            logger.debug(
                f"Reported TCB {component_name} from certificate matches the attestation report."
            )
        else:
            logger.error(
                f"Reported TCB {component_name} mismatch. Certificate: {cert_value}, Report: {report_value}"
            )
            return False

    # Check Chip ID (Hardware ID in report)
    cert_hwid = get_extension_value(cert, SnpOid.HwId.value)
    report_hwid = report.get_hwid()

    if cert_hwid == report_hwid:
        logger.debug("Chip ID from certificate matches the attestation report.")
    else:
        logger.error(
            f"Chip ID mismatch. Certificate: {cert_hwid}, Report: {report_hwid}"
        )
        return False

    return True


def cert_verify_report(report, cert):
    """
    cert_verify_report
    Description: Verify an attestation report against a VCEK certificate
    Inputs:
        report: Attestation report object
        cert: x509.Certificate object (VCEK)
    Output: bool: True if verification succeeds, False otherwise
    """
    if not cert_verify_report_components(report, cert):
        logger.error("The attestation report values do not match the VCEK certificate.")
        return False
    else:
        logger.info(
            "Report components verified successfully against the VCEK certificate."
        )

    report_bytes = report.to_bytes()
    signed_bytes = report_bytes[0:672]  # Use the first 672 bytes (0x2A0)

    # digest = hashes.Hash(hashes.SHA384())
    # digest.update(signed_bytes)
    # hashed_info = digest.finalize()

    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError(f"Unsupported public key type: {type(public_key)}")

    r = int.from_bytes(report.signature.get_trimmed_r(), "little")
    s = int.from_bytes(report.signature.get_trimmed_s(), "little")
    # print(f"R: {r}")
    # print(f"S: {s}")
    signature = utils.encode_dss_signature(r, s)
    # print(f"Encoded signature: {signature.hex()}")
    # print(f"Hashed info: {hashed_info.hex()}")

    try:
        public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature as e:
        logger.error(f"Error: Invalid signature. Details: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during signature verification: {str(e)}")
        return False


def check_certificate_against_crl(cert, crl):
    """
    check_certificate_against_crl
    Description: Check if a certificate is revoked using a Certificate Revocation List
    Inputs:
        cert: x509.Certificate object to check
        crl: x509.CertificateRevocationList object
    Output: bool: True if certificate is NOT revoked, False if it is revoked
    """
    # Check CRL is current
    current_time = datetime.datetime.now(datetime.timezone.utc)
    if crl.next_update_utc and current_time > crl.next_update_utc:
        logger.error(f"CRL is expired (next update field is {crl.next_update_utc})")
        return False

    # Get the certificate's serial number
    cert_serial = cert.serial_number

    # Check if the certificate is in the CRL
    try:
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert_serial)
        if revoked_cert is not None:
            logger.error(
                f"Certificate with serial {cert_serial} is REVOKED. Revocation date: {revoked_cert.revocation_date}"
            )
            try:
                reason_ext = revoked_cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.CRL_REASON
                )
                logger.error(f"  Revocation reason: {reason_ext.value.reason}")
            except x509.ExtensionNotFound:
                pass
            return False
        else:
            logger.debug(f"Certificate with serial {cert_serial} is NOT revoked.")
            return True
    except Exception as e:
        logger.error(f"Error checking CRL for certificate serial {cert_serial}: {e}")
        return False
