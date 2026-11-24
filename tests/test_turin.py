# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Turin (Zen 5, CPUID family 0x1A) specifics: the TCB gains an FMC SPL that is
# part of the VCEK derivation, and the chip ID shrinks to 8 bytes.
#
#   turin_report.bin      version-5 attestation report
#   turin_vcek.der        its VCEK: sev-fetch vcek -p turin -e der -r turin_report.bin
#   turin_vcek_fmc0.der   the same KDS URL *without* the fmcSPL parameter: the
#                         KDS then serves the chip's FMC=0 VCEK, a different
#                         key, so a verifier that ignores the FMC SPL cannot
#                         verify Turin reports
#
# Values asserted below are read from the files in ``_fixture_values``.

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509

from sev_pytools import AttestationReport, PolicyValidationError, ProcType
from sev_pytools.certs import (
    SnpOid,
    cert_verify_report,
    cert_verify_report_components,
    get_extension_value,
)
from sev_pytools.fetch import cpuid_to_processor_type, request_vcek_kds
from sev_pytools.tas_verify import (
    _tcb_str,
    build_policy,
    parse_min_tcb,
    usable_table_certs,
)
from sev_pytools.verify import verify_certificate_chain

DATA = Path(__file__).parent / "data"
REPORT_FILE = DATA / "turin_report.bin"
VCEK_FILE = DATA / "turin_vcek.der"
VCEK_FMC0_FILE = DATA / "turin_vcek_fmc0.der"

HWID = "0006423f30542f5d"
TCB = {"fmc": 1, "bl": 3, "tee": 3, "snp": 7, "ucode": 102}
MEASUREMENT = (
    "da80ee282e35a81af29d098e274b419d8bcad3728acdc76a1dab136ee4b6fdc2"
    "e8e79b48cada632254c3f9d0e9cf0f80"
)


@pytest.fixture(scope="module")
def report() -> AttestationReport:
    return AttestationReport.unpack(REPORT_FILE.read_bytes())


@pytest.fixture(scope="module")
def milan_report() -> AttestationReport:
    return AttestationReport.unpack((DATA / "milan_report.bin").read_bytes())


@pytest.fixture(scope="module")
def vcek() -> x509.Certificate:
    return x509.load_der_x509_certificate(VCEK_FILE.read_bytes())


@pytest.fixture(scope="module")
def vcek_fmc0() -> x509.Certificate:
    return x509.load_der_x509_certificate(VCEK_FMC0_FILE.read_bytes())


@pytest.fixture(autouse=True, scope="module")
def _fixture_values(report, vcek, vcek_fmc0):
    """Pin the fixture values the tests below rely on; update if the files change."""
    assert report.version == 5
    assert (report.cpuid.family_id, report.cpuid.model_id) == (0x1A, 0x11)
    assert report.get_hwid() == HWID
    assert report.measurement.hex() == MEASUREMENT
    for tcb in (report.reported_tcb, report.current_tcb):
        assert (tcb.fmc, tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode) == tuple(
            TCB.values()
        )
    assert get_extension_value(vcek, SnpOid.Fmc.value) == 1
    assert get_extension_value(vcek_fmc0, SnpOid.Fmc.value) == 0


def test_turin_report_fields(report):
    assert report.supports_cpuid
    assert cpuid_to_processor_type(report.cpuid) is ProcType.TURIN
    assert report.supports_tcb_fmc
    assert len(report.get_hwid()) == 16  # 8-byte chip ID ...
    assert report.chip_id[8:] == bytes(56)  # ... zero-padded in the report


def test_turin_vceks_differ_only_by_fmc(report, vcek, vcek_fmc0):
    assert get_extension_value(vcek, SnpOid.Fmc.value) == report.reported_tcb.fmc
    assert get_extension_value(vcek_fmc0, SnpOid.Fmc.value) != report.reported_tcb.fmc
    for oid in (SnpOid.HwId, SnpOid.BootLoader, SnpOid.Tee, SnpOid.Snp, SnpOid.Ucode):
        assert get_extension_value(vcek, oid.value) == get_extension_value(
            vcek_fmc0, oid.value
        )
    # the FMC SPL is part of the VCEK derivation: different SPL, different key
    assert vcek.public_key().public_numbers() != vcek_fmc0.public_key().public_numbers()


def _kds_session(der: bytes) -> MagicMock:
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200, content=der)
    return session


def test_vcek_kds_url_includes_fmc_spl_for_turin_only(report, milan_report):
    der = VCEK_FILE.read_bytes()
    with patch(
        "sev_pytools.fetch.create_retry_session", return_value=_kds_session(der)
    ) as s:
        request_vcek_kds(ProcType.TURIN, report=report)
        url = s.return_value.get.call_args.args[0]
    assert url == (
        f"https://kdsintf.amd.com/vcek/v1/Turin/{HWID}"
        "?blSPL=03&teeSPL=03&snpSPL=07&ucodeSPL=102&fmcSPL=01"
    )
    with patch(
        "sev_pytools.fetch.create_retry_session", return_value=_kds_session(der)
    ) as s:
        request_vcek_kds(ProcType.MILAN, report=milan_report)
        url = s.return_value.get.call_args.args[0]
    assert url.startswith("https://kdsintf.amd.com/vcek/v1/Milan/")
    assert "fmcSPL" not in url


def test_turin_chain_and_report_signature(report, vcek):
    assert verify_certificate_chain({"vcek": vcek}, ProcType.TURIN)
    assert cert_verify_report_components(report, vcek)
    assert cert_verify_report(report, vcek)


def test_wrong_fmc_vcek_is_a_component_mismatch_not_a_signature_error(
    report, vcek_fmc0, caplog
):
    assert not cert_verify_report_components(report, vcek_fmc0)
    assert "Reported TCB FMC mismatch. Certificate: 0, Report: 1" in caplog.text
    assert not cert_verify_report(report, vcek_fmc0)


def test_table_check_rejects_wrong_fmc_vcek(report, vcek, vcek_fmc0, caplog):
    assert usable_table_certs({"vcek": vcek}, report, ProcType.TURIN) == {"vcek": vcek}
    assert usable_table_certs({"vcek": vcek_fmc0}, report, ProcType.TURIN) == {}
    assert "stale certificate table" in caplog.text


def test_tcb_string_and_min_tcb_with_fmc(report, milan_report):
    assert _tcb_str(report.reported_tcb) == "1.3.3.7.102"
    assert _tcb_str(milan_report.reported_tcb) == "4.0.29.222"  # no FMC on Milan
    assert parse_min_tcb("fmc=1,snp=7") == {"fmc": 1, "snp": 7}
    assert build_policy(MEASUREMENT, min_tcb={"fmc": 1, "snp": 7}).validate_report(
        report
    )
    with pytest.raises(PolicyValidationError, match="reported_tcb.fmc"):
        build_policy(MEASUREMENT, min_tcb={"fmc": 2}).validate_report(report)
