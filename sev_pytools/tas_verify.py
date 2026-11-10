# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Command-line utility that decides whether a TEE Attestation Service (TAS)
# instance runs inside a genuine, correctly measured AMD SEV-SNP confidential
# VM, by requesting its TAS-attestation report and verifying it locally.
#
# Flow:
#   1. Generate a nonce and POST it to /attest/v0/report over a TLS connection
#      whose leaf certificate we capture.
#   2. Expect REPORT_DATA == SHA-512("TAS-attest/v1" || nonce || SHA-256(that
#      certificate)); this binds the report to the TLS session, so a plain
#      proxy cannot relay a genuine CVM's report.
#   3. Verify the report signature chain (built-in AMD root -> ASK -> VCEK; the
#      VCEK comes from the response's certificate table, a local cache keyed by
#      chip and TCB, or the AMD KDS) and a current CRL.
#   4. Apply the trust policy: expected launch measurement, VMPL 0, debug
#      disabled (never negotiable), migration disabled, optional TCB floor
#      (or a policy file).
#
# Outcome is the last line of output and the exit status:
#   TRUSTED (0), NOT TRUSTED (1, verification failed), UNDETERMINED (2, could
#   not obtain or verify the report: network, KDS, budget, misconfiguration).

import argparse
import base64
import binascii
import datetime
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
from typing import Dict, Optional
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .attestation_report import AttestationReport
from .builtin_certs import builtin_ark
from .certs import (
    SnpOid,
    complete_certificates,
    get_extension_value,
    load_crl,
    parse_cert_table,
)
from .fetch import (
    CERTS_DIR_HELP,
    CertFormat,
    Endorsement,
    ProcType,
    cpuid_to_processor_type,
    default_certs_dir,
    request_crl_kds,
    request_vcek_kds,
    write_cert,
)
from .policy import AttestationPolicy, PolicyValidationError
from .sev_logging import (
    get_logger,
    log_section_header,
    log_verification_step,
    setup_cli_logging,
)
from .verify import policy_verify_attestation_report, verify_attestation_bytes

logger = get_logger(__name__)

REPORT_PATH = "/attest/v0/report"
MANAGEMENT_KEY_HEADER = "X-MANAGEMENT-API-KEY"
MANAGEMENT_KEY_ENV = "TAS_MANAGEMENT_API_KEY"
PROVIDER = "sev_guest"
# Domain separator TAS mixes into REPORT_DATA; ties the signed value to this protocol version.
REPORT_DATA_DOMAIN = b"TAS-attest/v1"
# A TAS response is a few KiB (SNP) to ~130 KiB (TDX quote); anything larger is not TAS.
MAX_RESPONSE_BYTES = 1 << 20
TCB_FIELDS = ("bootloader", "tee", "snp", "microcode")
TCB_ALIASES = {"bl": "bootloader", "ucode": "microcode"}

EXIT_TRUSTED, EXIT_NOT_TRUSTED, EXIT_UNDETERMINED = 0, 1, 2


class TasVerifyError(Exception):
    """Verification failed: the report is genuine evidence that TAS is NOT TRUSTED."""


class TasUndeterminedError(Exception):
    """No verdict possible: report not obtained/verifiable for infrastructure reasons."""


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
def fetch_report(
    url: str,
    nonce: bytes,
    management_key: Optional[str] = None,
    ca_file: Optional[str] = None,
    timeout: float = 45.0,
):
    """
    fetch_report
    Description: Request the attestation report over a single TLS connection
                 and return it together with the leaf certificate of that very
                 connection (so the TLS binding cannot be satisfied by a proxy
                 that terminates TLS separately).
    Inputs:
        url: TAS base URL or full report URL (https://host[:port][/attest/v0/report])
        nonce: Random bytes (16-64) to bind the report to
        management_key: Value for X-MANAGEMENT-API-KEY if TAS requires it
        ca_file: PEM bundle to verify the server certificate against. Without it the
                 certificate is not validated against a CA; attestation vouches for it
        timeout: Socket timeout in seconds. Report generation is serialised in
                 TAS and a TDX quote can take up to 30 s, hence the generous default
    Output: (response_json: dict, tls_leaf_der: bytes)
    Raises: TasUndeterminedError (cannot reach/talk to TAS), TasVerifyError (TAS
            states it is not a confidential VM)
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if parts.scheme != "https":
        raise TasUndeterminedError(
            "TAS URL must use https (the report is bound to the TLS certificate)"
        )
    if not parts.hostname:
        raise TasUndeterminedError(f"Invalid TAS URL: {url!r}")
    host, port = parts.hostname, parts.port or 443
    path = parts.path.rstrip("/") or ""
    if not path.endswith(REPORT_PATH):
        path += REPORT_PATH

    if ca_file:
        context = ssl.create_default_context(cafile=ca_file)
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "sev-verify-tas",
    }
    if management_key:
        headers[MANAGEMENT_KEY_HEADER] = management_key
    request_body = json.dumps({"nonce": nonce.hex()}).encode()

    logger.info(f"Requesting attestation report from https://{host}:{port}{path}")
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    try:
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as e:
            raise TasUndeterminedError(f"Cannot connect to {host}:{port}: {e}") from e
        tls_leaf_der = conn.sock.getpeercert(binary_form=True)
        conn.request("POST", path, body=request_body, headers=headers)
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as e:
        raise TasUndeterminedError(f"Request to TAS failed: {e}") from e
    finally:
        conn.close()

    if len(body) > MAX_RESPONSE_BYTES:
        raise TasUndeterminedError(
            f"TAS response exceeds {MAX_RESPONSE_BYTES} bytes; not a TAS-attestation response"
        )
    try:
        payload = json.loads(body)
    except ValueError:
        raise TasUndeterminedError(
            f"TAS returned HTTP {response.status} with a non-JSON body: {body[:200]!r}"
        ) from None
    if response.status == 200:
        logger.info(
            f"TLS leaf certificate SHA-256: {hashlib.sha256(tls_leaf_der).hexdigest()}"
        )
        return payload, tls_leaf_der

    error = payload.get("error", payload) if isinstance(payload, dict) else payload
    if response.status == 501:
        # TAS itself says it has no TSM report slot: a definitive negative
        raise TasVerifyError(f"TAS is not running in a confidential VM: {error}")
    if response.status == 401:
        raise TasUndeterminedError(
            "TAS requires the management API key for this endpoint "
            f"(--management-key or ${MANAGEMENT_KEY_ENV})"
        )
    if response.status in (429, 503):
        retry_after = response.getheader("Retry-After")
        raise TasUndeterminedError(
            f"TAS is not accepting attestation requests right now (HTTP {response.status}"
            f"{', retry after ' + retry_after + 's' if retry_after else ''})"
        )
    raise TasUndeterminedError(f"TAS returned HTTP {response.status}: {error}")


def expected_report_data(nonce: bytes, tls_leaf_der: bytes) -> bytes:
    """REPORT_DATA TAS must have embedded: SHA-512(domain || nonce || SHA-256(TLS leaf DER))."""
    return hashlib.sha512(
        REPORT_DATA_DOMAIN + nonce + hashlib.sha256(tls_leaf_der).digest()
    ).digest()


def check_response(payload: dict, nonce: bytes, tls_leaf_der: bytes) -> bytes:
    """
    check_response
    Description: Validate the TAS response envelope and return the raw report
    Inputs: payload (dict), nonce (bytes), tls_leaf_der (bytes)
    Output: bytes: the raw SEV-SNP attestation report
    Raises: TasVerifyError on any mismatch
    """
    if not isinstance(payload, dict):
        raise TasVerifyError("TAS response is not a JSON object")
    provider = payload.get("provider")
    if provider != PROVIDER:
        raise TasVerifyError(
            f"TAS reports TEE provider '{provider}'; this tool verifies AMD SEV-SNP "
            f"('{PROVIDER}') only"
        )
    if payload.get("nonce") != nonce.hex():
        raise TasVerifyError("TAS echoed a different nonce than was sent")
    tls_fp = hashlib.sha256(tls_leaf_der).hexdigest()
    if payload.get("tls_cert_sha256") != tls_fp:
        raise TasVerifyError(
            "TAS bound the report to a different TLS certificate than the one presented "
            f"to us (TAS: {payload.get('tls_cert_sha256')}, seen: {tls_fp}); "
            "a TLS-terminating proxy may be in the path"
        )
    try:
        report = base64.b64decode(payload["report"], validate=True)
    except (KeyError, TypeError, ValueError) as e:
        raise TasVerifyError(f"Response has no valid base64 'report' field: {e}") from e
    log_verification_step("Response envelope (provider, nonce, TLS binding)", "PASS")
    return report


def certificates_from_table(payload: dict) -> Dict[str, object]:
    """Certificates from the hypervisor's table in the response; {} if absent or malformed.

    The table is host-supplied and untrusted: a broken one is ignored (the
    verifier falls back to its cache or the KDS) and never a reason to fail.
    """
    aux = payload.get("auxblob")
    if not aux:
        return {}
    try:
        table = parse_cert_table(base64.b64decode(aux, validate=True))
    except (binascii.Error, ValueError, TypeError) as e:
        logger.warning(f"Ignoring malformed certificate table from TAS: {e}")
        return {}
    return {k: v for k, v in table.items() if k in ("vcek", "crl")}


def usable_table_certs(
    supplied: Dict[str, object], report: AttestationReport, proc_type: ProcType
) -> Dict[str, object]:
    """Hypervisor-supplied VCEK/CRL that are AMD-issued and for this report; others dropped.

    A stale table (host firmware updated, table not refreshed) or a wrong-chip
    table must not produce a verdict: the cache or the KDS still can.
    """
    usable = {}
    ark = builtin_ark(proc_type)
    vcek = supplied.get("vcek")
    if vcek is not None:
        tcb = report.reported_tcb
        expected = {
            SnpOid.HwId: report.get_hwid(),
            SnpOid.BootLoader: tcb.bootloader,
            SnpOid.Tee: tcb.tee,
            SnpOid.Snp: tcb.snp,
            SnpOid.Ucode: tcb.microcode,
        }
        try:
            ark = complete_certificates({"vcek": vcek})["ark"]
        except ValueError as e:
            logger.warning(f"Ignoring hypervisor-supplied VCEK: {e}")
        else:
            if all(
                get_extension_value(vcek, o.value) == v for o, v in expected.items()
            ):
                usable["vcek"] = vcek
            else:
                logger.warning(
                    "Ignoring hypervisor-supplied VCEK: issued for another chip or "
                    "TCB than the report's (stale certificate table?)"
                )
    crl = supplied.get("crl")
    if crl is not None:
        if _crl_signed_by(crl, ark):
            usable["crl"] = crl
        else:
            logger.warning(
                "Ignoring hypervisor-supplied CRL: not signed by the AMD ARK"
            )
    return usable


def _crl_signed_by(crl, ark) -> bool:
    try:  # quiet twin of certs.verify_crl: a bad table CRL is expected, not an error
        ark.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding=crl.signature_algorithm_parameters,
            algorithm=hashes.SHA384(),
        )
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
def parse_min_tcb(spec: str) -> Dict[str, int]:
    """Parse "bl=9,tee=0,snp=23,ucode=72" (any subset) into TCB field minimums."""
    minimums = {}
    for item in filter(None, re.split(r"[,\s]+", spec.strip())):
        name, sep, value = item.partition("=")
        name = TCB_ALIASES.get(name.lower(), name.lower())
        if not sep or name not in TCB_FIELDS or not value.isdigit():
            raise TasUndeterminedError(
                f"--min-tcb: bad component {item!r}; use e.g. bl=9,tee=0,snp=23,ucode=72"
            )
        minimums[name] = int(value)
    return minimums


def build_policy(
    measurement: str,
    vmpl: int = 0,
    allow_migration: bool = False,
    min_report_version: int = 2,
    min_tcb: Optional[Dict[str, int]] = None,
) -> AttestationPolicy:
    """Trust policy for a TAS CVM from command-line arguments.

    Debug-enabled guests are always rejected: with the debug policy bit set the
    hypervisor can read the guest's memory, which defeats the purpose. A TCB
    floor applies to both the TCB the VCEK vouches for (reported) and the TCB
    actually running (current).
    """
    rules = {
        "measurement": {"exact_match": normalise_measurement(measurement)},
        "vmpl": {"exact_match": vmpl},
        "version": {"min_value": min_report_version},
        "policy": {"debug_allowed": False, "migrate_ma_allowed": allow_migration},
    }
    if min_tcb:
        floor = {field: {"min_value": value} for field, value in min_tcb.items()}
        rules["reported_tcb"] = floor
        rules["current_tcb"] = dict(floor)
    return AttestationPolicy(
        policy_data={
            "metadata": {"name": "sev-verify-tas", "version": "1"},
            "validation_rules": rules,
        }
    )


def normalise_measurement(measurement: str) -> str:
    """Accept 96 hex characters with optional colons/spaces/case; return lower-case hex."""
    cleaned = measurement.lower().replace(":", "").replace(" ", "")
    try:
        if len(bytes.fromhex(cleaned)) != 48:
            raise ValueError
    except ValueError:
        raise TasUndeterminedError(
            "--measurement must be the 48-byte launch measurement as 96 hex characters"
        ) from None
    return cleaned


def with_measurement(policy: AttestationPolicy, measurement: str) -> AttestationPolicy:
    """Policy file plus a command-line measurement: the measurement overrides."""
    rules = policy.policy.setdefault("validation_rules", {})
    rules["measurement"] = {"exact_match": normalise_measurement(measurement)}
    return policy


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _tcb_str(tcb) -> str:
    return ".".join(str(getattr(tcb, f)) for f in TCB_FIELDS)


def _processor(report: AttestationReport, hint: Optional[ProcType] = None) -> ProcType:
    """Family for KDS URLs: from the report's CPUID (v3+), else the hint, else Genoa."""
    fallback = hint or ProcType.GENOA
    if report.supports_cpuid:
        try:
            return cpuid_to_processor_type(report.cpuid)
        except ValueError as e:
            logger.warning(f"{e}; assuming {fallback.value} for KDS requests")
    return fallback


def current_crl(certs_dir: str, proc_type: ProcType, candidate=None):
    """
    current_crl
    Description: Return a CRL that is still within its validity window: the one
                 TAS supplied, else the cached one, else a fresh one from the KDS
                 (which is then cached). Never returns an expired CRL.
    Inputs: certs_dir (cache directory), proc_type (ProcType), candidate (CRL or None)
    Output: x509.CertificateRevocationList
    Raises: TasUndeterminedError if no current CRL can be obtained
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    def fresh(crl):
        return crl is not None and not (
            crl.next_update_utc and now > crl.next_update_utc
        )

    if fresh(candidate):
        logger.info("Using CRL supplied by the hypervisor's certificate table")
        return candidate
    cached = None
    if os.path.isdir(certs_dir):
        try:
            cached = load_crl(certs_dir)
        except ValueError:
            cached = None
    if fresh(cached):
        return cached
    if cached is not None:
        logger.info(
            f"Cached CRL expired on {cached.next_update_utc:%Y-%m-%d}; refreshing"
        )
    try:
        crl = request_crl_kds(proc_type, Endorsement.VCEK)
    except Exception as e:
        state = "expired" if cached is not None else "empty"
        raise TasUndeterminedError(
            f"No current CRL: cache {state} and the AMD KDS is unreachable ({e})"
        ) from e
    write_cert(certs_dir, "CRL", crl, CertFormat.PEM, Endorsement.VCEK)
    return crl


def cached_or_kds_vcek(report: AttestationReport, proc_type: ProcType, vcek_dir: str):
    """VCEK for the report's chip and reported TCB: from <vcek_dir>/vcek.pem, else the KDS."""
    vcek_file = os.path.join(vcek_dir, "vcek.pem")
    if os.path.exists(vcek_file):
        with open(vcek_file, "rb") as f:
            data = f.read()
        try:
            vcek = x509.load_pem_x509_certificate(data)
        except ValueError:
            logger.warning(f"Cached VCEK {vcek_file} is unreadable; fetching again")
        else:
            logger.info(f"Using cached VCEK {vcek_file}")
            return vcek
    try:
        vcek = request_vcek_kds(proc_type, report=report)
    except Exception as e:
        raise TasUndeterminedError(
            f"VCEK for chip {report.get_hwid()[:16]}... TCB "
            f"{_tcb_str(report.reported_tcb)} is not cached and the AMD KDS request "
            f"failed ({e}); retry with network access or a pre-populated --certs"
        ) from e
    write_cert(vcek_dir, "VCEK", vcek, CertFormat.PEM, Endorsement.VCEK)
    return vcek


def verify_tas(
    url: str,
    policy: AttestationPolicy,
    management_key: Optional[str] = None,
    ca_file: Optional[str] = None,
    certs_dir: Optional[str] = None,
    save_report: Optional[str] = None,
    timeout: float = 45.0,
    require_tcb_match: bool = False,
    processor: Optional[ProcType] = None,
) -> AttestationReport:
    """
    verify_tas
    Description: Fetch and fully verify a TAS instance's TAS-attestation report
    Inputs:
        url: TAS base URL
        policy: AttestationPolicy to apply (see build_policy)
        management_key: X-MANAGEMENT-API-KEY value if TAS requires it
        ca_file: Optional CA bundle for ordinary TLS validation in addition to attestation
        certs_dir: Cache directory (default: default_certs_dir()): <certs_dir>/crl.pem
                   plus one VCEK per <chip id>-<reported TCB> subdirectory. Filled
                   from the response's certificate table or the KDS; reused offline
        save_report: Optional path to write the raw report to (for sev-print)
        timeout: HTTP timeout in seconds for the report request
        require_tcb_match: Fail unless the reported TCB equals the current TCB
        processor: Family for KDS requests when the report has no CPUID (v2); default Genoa
    Output: AttestationReport (verified)
    Raises: TasVerifyError (NOT TRUSTED), TasUndeterminedError (no verdict)
    """
    if certs_dir is None:
        certs_dir = default_certs_dir()
    nonce = os.urandom(32)
    log_section_header("FETCHING REPORT FROM TAS")
    payload, tls_leaf_der = fetch_report(url, nonce, management_key, ca_file, timeout)
    report_bytes = check_response(payload, nonce, tls_leaf_der)
    if save_report:
        with open(save_report, "wb") as f:
            f.write(report_bytes)
        logger.info(f"Raw report written to {save_report}")

    try:
        report = AttestationReport.unpack(report_bytes)
    except Exception as e:
        raise TasVerifyError(f"TAS returned an unparsable SEV-SNP report: {e}") from e

    signer = report.key_info.signing_key_name()
    if signer != "vcek":
        raise TasVerifyError(
            f"Report is signed with the {signer.upper()} key; this tool verifies "
            "VCEK-signed reports only"
        )

    proc_type = _processor(report, processor)
    supplied = usable_table_certs(certificates_from_table(payload), report, proc_type)
    # One VCEK per chip and reported TCB, so a cache can serve several TAS instances
    vcek_dir = os.path.join(
        certs_dir, f"{report.get_hwid()[:16]}-{_tcb_str(report.reported_tcb)}"
    )
    from_table = "vcek" in supplied
    if from_table:
        logger.info("Using VCEK from the hypervisor's certificate table")
        vcek = supplied["vcek"]
    else:
        vcek = cached_or_kds_vcek(report, proc_type, vcek_dir)
    crl = current_crl(certs_dir, proc_type, supplied.get("crl"))

    log_section_header("VERIFYING REPORT")
    try:
        report, _, _ = verify_attestation_bytes(
            report_bytes,
            certificates={"vcek": vcek},
            crl=crl,
            processor_model=proc_type.name.lower(),
        )
        policy_verify_attestation_report(
            report, policy, expected_report_data(nonce, tls_leaf_der)
        )
    except (ValueError, PolicyValidationError) as e:
        raise TasVerifyError(str(e)) from e
    if from_table:  # cache the table's VCEK only once it has verified
        write_cert(vcek_dir, "VCEK", vcek, CertFormat.PEM, Endorsement.VCEK)

    if report.reported_tcb != report.current_tcb:
        message = (
            f"Reported TCB {_tcb_str(report.reported_tcb)} differs from the current "
            f"TCB {_tcb_str(report.current_tcb)} (platform firmware newer than the "
            "TCB it attests to)"
        )
        if require_tcb_match:
            raise TasVerifyError(message)
        logger.warning(message)
    else:
        log_verification_step("Reported TCB equals current TCB", "PASS")
    return report


def _summary(report: AttestationReport) -> str:
    policy = report.policy
    lines = [
        f"  Measurement : {report.measurement.hex()}",
        f"  VMPL        : {report.vmpl}",
        f"  Guest policy: debug={'on' if policy.debug_allowed else 'off'} "
        f"migrate={'on' if policy.migrate_ma_allowed else 'off'} "
        f"smt={'on' if policy.smt_allowed else 'off'}",
        f"  TCB         : reported {_tcb_str(report.reported_tcb)}  "
        f"current {_tcb_str(report.current_tcb)}  (bl.tee.snp.ucode)",
        f"  Chip ID     : {report.chip_id.hex()[:32]}...",
    ]
    return "\n".join(lines)


def main():
    """
    main
    Description: Decide whether a TAS instance runs in a trusted SEV-SNP CVM
    Arguments:
        url: TAS base URL, e.g. https://tas.example.com
        -m, --measurement: Expected launch measurement (96 hex chars); required unless --policy
        -q, --policy: Policy file to apply; -m additionally overrides its measurement
        -k, --management-key: X-MANAGEMENT-API-KEY (default: $TAS_MANAGEMENT_API_KEY)
        -c, --certs: VCEK/CRL cache directory (default: $SEV_PYTOOLS_CERTS_DIR or ~/.cache/sev_pytools)
        --ca-file: CA bundle to also validate the TLS certificate conventionally
        --vmpl, --allow-migration: relax the built-in rules (debug is never allowed)
        --min-tcb: TCB floor, e.g. bl=9,tee=0,snp=23,ucode=72
        --require-tcb-match: fail unless reported TCB == current TCB (default: warn)
        -p, --processor: family for KDS requests if the report has no CPUID (v2; default genoa)
        --save-report: write the raw report to this file
        --timeout: seconds to wait for TAS to produce the report (default: 45)
        -v/--verbose, --quiet, --log-file: logging
    Exit status: 0 TRUSTED, 1 NOT TRUSTED, 2 UNDETERMINED
    Examples:
        sev-verify-tas https://10.0.0.5 -m cf9bcad1...5627
        sev-verify-tas https://tas.example.com -m <hex> -k "$TAS_MANAGEMENT_API_KEY" -c ./cache
        sev-verify-tas https://tas.example.com -m <hex> --min-tcb bl=9,snp=23,ucode=72
    """
    parser = argparse.ArgumentParser(
        description="Verify that a TAS instance runs in a trusted AMD SEV-SNP CVM"
    )
    parser.add_argument("url", help="TAS base URL (https://host[:port])")
    parser.add_argument(
        "-m", "--measurement", help="Expected launch measurement (96 hex characters)"
    )
    parser.add_argument(
        "-q",
        "--policy",
        help="Policy file to apply instead of the built-in rules "
        "(with -m, the measurement overrides the file's)",
    )
    parser.add_argument(
        "-k",
        "--management-key",
        default=os.environ.get(MANAGEMENT_KEY_ENV),
        help=f"Management API key if TAS requires it (default: ${MANAGEMENT_KEY_ENV})",
    )
    parser.add_argument(
        "-c",
        "--certs",
        help=f"VCEK/CRL cache directory (default: {CERTS_DIR_HELP})",
    )
    parser.add_argument(
        "--ca-file", help="CA bundle to additionally validate the TLS certificate"
    )
    parser.add_argument(
        "--vmpl", type=int, default=0, help="Required VMPL (default: 0)"
    )
    parser.add_argument(
        "--allow-migration", action="store_true", help="Accept migration-enabled guests"
    )
    parser.add_argument(
        "--min-tcb",
        help="Minimum TCB, e.g. bl=9,tee=0,snp=23,ucode=72 (applies to reported and current TCB)",
    )
    parser.add_argument(
        "--require-tcb-match",
        action="store_true",
        help="Fail unless the reported TCB equals the current TCB (default: warn only)",
    )
    parser.add_argument(
        "-p",
        "--processor",
        choices=[p.name.lower() for p in ProcType],
        help="Processor family for KDS requests, only used if the report carries no "
        "CPUID (version 2; default: genoa)",
    )
    parser.add_argument("--save-report", help="Write the raw report to this file")
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="Seconds to wait for TAS to produce the report (default: 45; a TDX "
        "quote can take up to 30 s)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose mode"
    )
    parser.add_argument("--quiet", action="store_true", help="Warnings and errors only")
    parser.add_argument("--log-file", help="Path to log file (optional)")
    args = parser.parse_args()

    setup_cli_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)
    if not args.policy and not args.measurement:
        parser.error("one of --measurement or --policy is required")

    try:
        if args.policy:
            policy = AttestationPolicy(policy_file=args.policy)
            if args.measurement:
                policy = with_measurement(policy, args.measurement)
        else:
            policy = build_policy(
                args.measurement,
                args.vmpl,
                args.allow_migration,
                min_tcb=parse_min_tcb(args.min_tcb) if args.min_tcb else None,
            )

        report = verify_tas(
            args.url,
            policy,
            management_key=args.management_key,
            ca_file=args.ca_file,
            certs_dir=args.certs,
            save_report=args.save_report,
            timeout=args.timeout,
            require_tcb_match=args.require_tcb_match,
            processor=ProcType[args.processor.upper()] if args.processor else None,
        )
    except TasVerifyError as e:
        logger.error(f"NOT TRUSTED: {e}")
        print(f"\n  reason: {e}\nNOT TRUSTED: {args.url}")
        return EXIT_NOT_TRUSTED
    except TasUndeterminedError as e:
        logger.error(f"UNDETERMINED: {e}")
        print(f"\n  reason: {e}\nUNDETERMINED: {args.url} (no verdict; see reason)")
        return EXIT_UNDETERMINED
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        print(
            f"\n  reason: unexpected error: {e}\nUNDETERMINED: {args.url} (no verdict)"
        )
        return EXIT_UNDETERMINED

    print(
        f"\n{_summary(report)}\nTRUSTED: {args.url} is running in a verified AMD SEV-SNP CVM"
    )
    return EXIT_TRUSTED


if __name__ == "__main__":
    sys.exit(main())
