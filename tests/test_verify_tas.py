# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Tests for sev-verify-tas (TAS-attestation verification) and the GHCB
# certificate table parser it relies on.

import base64
import hashlib
import http.server
import json
import ssl
import struct
import threading
import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from sev_pytools import AttestationReport, ProcType, builtin_ark, builtin_ask
from sev_pytools.certs import SnpOid, parse_cert_table
from sev_pytools.policy import PolicyValidationError
from sev_pytools.verify import verify_certificate_chain_with_crl
from sev_pytools.verify_tas import (
    MANAGEMENT_KEY_HEADER,
    MAX_RESPONSE_BYTES,
    TasUndeterminedError,
    TasVerifyError,
    build_policy,
    certificates_from_table,
    check_response,
    current_crl,
    expected_report_data,
    fetch_report,
    main,
    parse_min_tcb,
    usable_table_certs,
    verify_tas,
)

MEASUREMENT = "ab" * 48
NONCE = bytes(range(32))


def _report(signing_key=0, current_snp=23, reported_snp=23):
    """Synthetic 1184-byte SNP report: version 2, VCEK-signed unless told otherwise."""
    b = bytearray(1184)
    b[0] = 2  # version
    b[56], b[62], b[63] = 9, current_snp, 72  # current TCB bl/snp/ucode
    b[72] = signing_key << 2  # key_info: bits 2-4 = signing key (0 VCEK, 1 VLEK)
    b[384], b[390], b[391] = 9, reported_snp, 72  # reported TCB
    b[416:480] = bytes(range(64))  # chip id
    return bytes(b)


REPORT = _report()


# --------------------------------------------------------------------------- #
# Certificate table (auxblob)
# --------------------------------------------------------------------------- #
def _table(*entries):
    """Build a GHCB cert table: entries = [(guid, data), ...]."""
    header_len = 24 * (len(entries) + 1)
    header, body, offset = b"", b"", header_len
    for guid, data in entries:
        header += struct.pack("<16sII", guid.bytes, offset, len(data))
        body += data
        offset += len(data)
    return header + bytes(24) + body


VCEK_GUID = uuid.UUID("63da758d-e664-4564-adc5-f4b93be8accd")
ASK_GUID = uuid.UUID("4ab7b379-bbac-4fe4-a02f-05aef327c782")
CRL_GUID = uuid.UUID("92f81bc3-5811-4d3d-97ff-d19f88dc67ea")


def test_parse_cert_table_roundtrip():
    cert = builtin_ask(ProcType.GENOA)  # any DER certificate will do
    der = cert.public_bytes(serialization.Encoding.DER)
    other = uuid.UUID("11111111-2222-3333-4444-555555555555")
    table = _table((VCEK_GUID, der), (ASK_GUID, der), (other, b"opaque"))
    parsed = parse_cert_table(table)
    assert parsed["vcek"] == cert and parsed["ask"] == cert
    assert parsed[str(other)] == b"opaque"


def test_parse_cert_table_empty_and_zero():
    assert parse_cert_table(b"") == {}
    assert parse_cert_table(bytes(4096)) == {}


def test_parse_cert_table_rejects_out_of_bounds():
    bad = struct.pack("<16sII", VCEK_GUID.bytes, 24, 10_000) + bytes(24)
    with pytest.raises(ValueError, match="outside the table"):
        parse_cert_table(bad)


# --------------------------------------------------------------------------- #
# Response envelope / binding / policy
# --------------------------------------------------------------------------- #
def _payload(tls_der, **overrides):
    payload = {
        "provider": "sev_guest",
        "nonce": NONCE.hex(),
        "tls_cert_sha256": hashlib.sha256(tls_der).hexdigest(),
        "report": base64.b64encode(REPORT).decode(),
        "auxblob": None,
    }
    payload.update(overrides)
    return payload


def test_expected_report_data():
    der = b"cert"
    assert (
        expected_report_data(NONCE, der)
        == hashlib.sha512(
            b"TAS-attest/v1" + NONCE + hashlib.sha256(der).digest()
        ).digest()
    )


def test_check_response_ok():
    assert check_response(_payload(b"cert"), NONCE, b"cert") == REPORT


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"provider": "tdx_guest"}, "provider 'tdx_guest'"),
        ({"nonce": "00" * 32}, "different nonce"),
        ({"tls_cert_sha256": "00" * 32}, "different TLS certificate"),
        ({"report": "!!!"}, "base64"),
    ],
)
def test_check_response_rejects(overrides, match):
    with pytest.raises(TasVerifyError, match=match):
        check_response(_payload(b"cert", **overrides), NONCE, b"cert")


def test_check_response_detects_proxy_certificate():
    # TAS bound its own cert, but we were presented a different one (TLS-terminating proxy)
    with pytest.raises(TasVerifyError, match="proxy"):
        check_response(_payload(b"tas-cert"), NONCE, b"proxy-cert")


def test_build_policy_rules():
    policy = build_policy("AB:" * 47 + "AB")  # colon-separated, upper-case accepted
    rules = policy.policy["validation_rules"]
    assert rules["measurement"] == {"exact_match": MEASUREMENT}
    assert rules["vmpl"] == {"exact_match": 0}
    assert rules["policy"] == {"debug_allowed": False, "migrate_ma_allowed": False}
    relaxed = build_policy(MEASUREMENT, vmpl=2, allow_migration=True).policy[
        "validation_rules"
    ]
    assert relaxed["vmpl"] == {"exact_match": 2}
    assert relaxed["policy"]["migrate_ma_allowed"] is True
    assert relaxed["policy"]["debug_allowed"] is False  # never relaxable


@pytest.mark.parametrize("bad", ["", "abcd", "zz" * 48, "ab" * 47])
def test_build_policy_rejects_bad_measurement(bad):
    with pytest.raises(TasUndeterminedError, match="96 hex"):
        build_policy(bad)


def test_min_tcb_parsing_and_rules():
    assert parse_min_tcb("bl=9,tee=0,snp=23,ucode=72") == {
        "bootloader": 9,
        "tee": 0,
        "snp": 23,
        "microcode": 72,
    }
    assert parse_min_tcb("SNP=23 microcode=72") == {"snp": 23, "microcode": 72}
    rules = build_policy(MEASUREMENT, min_tcb={"snp": 23}).policy["validation_rules"]
    assert rules["reported_tcb"] == {"snp": {"min_value": 23}}
    assert rules["current_tcb"] == {"snp": {"min_value": 23}}
    assert "reported_tcb" not in build_policy(MEASUREMENT).policy["validation_rules"]
    for bad in ("snp", "snp=x", "foo=1", "snp=1," + "bl"):
        with pytest.raises(TasUndeterminedError, match="--min-tcb"):
            parse_min_tcb(bad)


def test_min_tcb_is_enforced_on_both_tcbs():
    policy = build_policy("00" * 48, min_tcb={"snp": 23})
    assert policy.validate_report(AttestationReport.unpack(_report()))
    with pytest.raises(PolicyValidationError, match="current_tcb.snp"):
        policy.validate_report(AttestationReport.unpack(_report(current_snp=22)))
    with pytest.raises(PolicyValidationError, match="reported_tcb.snp"):
        policy.validate_report(AttestationReport.unpack(_report(reported_snp=22)))


# --------------------------------------------------------------------------- #
# HTTPS fetch with TLS leaf capture (local TLS server)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "tas-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    d = tmp_path_factory.mktemp("tls")
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    state = {
        "status": 200,
        "body": None,
        "last_headers": None,
        "last_request": None,
        "payload_overrides": {},
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            state["last_headers"] = dict(self.headers)
            length = int(self.headers.get("Content-Length", 0))
            request_body = json.loads(self.rfile.read(length) or b"{}")
            state["last_request"] = (self.path, request_body)
            body = state["body"]
            if body is None:  # default: a valid payload for the posted nonce
                body = json.dumps(
                    _payload(
                        der, nonce=request_body["nonce"], **state["payload_overrides"]
                    )
                ).encode()
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # keep test output quiet
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield {
        "url": f"https://127.0.0.1:{httpd.server_port}",
        "der": der,
        "cert_file": str(d / "cert.pem"),
        "state": state,
    }
    httpd.shutdown()


@pytest.fixture
def server(tls_server):
    tls_server["state"].update(
        status=200, body=None, last_headers=None, payload_overrides={}
    )
    return tls_server


def test_fetch_report_captures_tls_leaf_and_sends_key(server):
    payload, der = fetch_report(server["url"], NONCE, management_key="secret")
    assert der == server["der"]
    assert payload["nonce"] == NONCE.hex()
    assert server["state"]["last_headers"][MANAGEMENT_KEY_HEADER] == "secret"
    assert server["state"]["last_request"] == (
        "/attest/v0/report",
        {"nonce": NONCE.hex()},
    )


def test_fetch_report_accepts_full_report_url_and_no_key(server):
    fetch_report(server["url"] + "/attest/v0/report", NONCE)
    assert MANAGEMENT_KEY_HEADER not in server["state"]["last_headers"]


def test_fetch_report_401_is_undetermined(server):
    server["state"].update(status=401, body=b'{"error": "Unauthorized"}')
    with pytest.raises(TasUndeterminedError, match="management API key"):
        fetch_report(server["url"], NONCE)


@pytest.mark.parametrize("status", [429, 503])
def test_fetch_report_busy_is_undetermined(server, status):
    server["state"].update(status=status, body=b'{"error": "busy"}')
    with pytest.raises(TasUndeterminedError, match=f"HTTP {status}"):
        fetch_report(server["url"], NONCE)


def test_fetch_report_501_is_not_trusted(server):
    server["state"].update(status=501, body=b'{"error": "no TSM report slot"}')
    with pytest.raises(TasVerifyError, match="not running in a confidential VM"):
        fetch_report(server["url"], NONCE)


def test_fetch_report_non_json(server):
    server["state"].update(status=502, body=b"<html>Bad Gateway</html>")
    with pytest.raises(TasUndeterminedError, match="non-JSON"):
        fetch_report(server["url"], NONCE)


def test_fetch_report_caps_response_size(server):
    server["state"].update(body=b'{"pad": "' + b"x" * MAX_RESPONSE_BYTES + b'"}')
    with pytest.raises(TasUndeterminedError, match="exceeds"):
        fetch_report(server["url"], NONCE)


@pytest.mark.parametrize(
    "url, match",
    [
        ("http://127.0.0.1:1", "https"),
        ("https://", "Invalid TAS URL"),
        ("https:///attest/v0/report", "Invalid TAS URL"),
    ],
)
def test_fetch_report_rejects_bad_urls(url, match):
    with pytest.raises(TasUndeterminedError, match=match):
        fetch_report(url, NONCE)


def test_fetch_report_connection_refused():
    with pytest.raises(TasUndeterminedError, match="Cannot connect"):
        fetch_report("https://127.0.0.1:1", NONCE)


def test_fetch_report_ca_file(server, tmp_path):
    # The server's own certificate as the CA bundle validates; any other bundle must fail
    payload, der = fetch_report(server["url"], NONCE, ca_file=server["cert_file"])
    assert der == server["der"] and payload["nonce"] == NONCE.hex()
    other = tmp_path / "ca.pem"
    other.write_bytes(
        builtin_ark(ProcType.GENOA).public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(TasUndeterminedError, match="Cannot connect"):
        fetch_report(server["url"], NONCE, ca_file=str(other))


# --------------------------------------------------------------------------- #
# Certificate table handling and CRL freshness
# --------------------------------------------------------------------------- #
def test_certificates_from_table_ignores_malformed(caplog):
    assert certificates_from_table({"auxblob": None}) == {}
    assert certificates_from_table({}) == {}
    bad = struct.pack("<16sII", VCEK_GUID.bytes, 24, 10_000) + bytes(24)
    assert certificates_from_table({"auxblob": base64.b64encode(bad).decode()}) == {}
    assert certificates_from_table({"auxblob": "not base64!"}) == {}
    assert "malformed certificate table" in caplog.text


def _crl(next_update):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "crl-test")])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(days=2))
        .next_update(next_update)
        .sign(key, hashes.SHA256())
    )


def test_current_crl_prefers_fresh_sources_and_refreshes_expired(tmp_path):
    fresh = _crl(datetime.now(timezone.utc) + timedelta(days=1))
    expired = _crl(datetime.now(timezone.utc) - timedelta(days=1))
    with patch("sev_pytools.verify_tas.request_crl_kds") as kds:
        # 1. table-supplied CRL is used when fresh, never the KDS
        assert current_crl(str(tmp_path), ProcType.GENOA, fresh) is fresh
        kds.assert_not_called()
        # 2. an expired table CRL and an empty cache -> KDS, result cached
        kds.return_value = fresh
        assert current_crl(str(tmp_path), ProcType.GENOA, expired) is fresh
        assert (tmp_path / "crl.pem").exists()
        kds.reset_mock()
        # 3. the cached fresh CRL is used offline
        assert current_crl(str(tmp_path), ProcType.GENOA).next_update_utc == (
            fresh.next_update_utc
        )
        kds.assert_not_called()
        # 4. expired cache + KDS down -> no verdict possible
        (tmp_path / "crl.pem").write_bytes(
            expired.public_bytes(serialization.Encoding.PEM)
        )
        kds.side_effect = ConnectionError("offline")
        with pytest.raises(TasUndeterminedError, match="expired"):
            current_crl(str(tmp_path), ProcType.GENOA)


def test_library_rejects_expired_crl_as_expired_not_revoked():
    # With the chain and CRL signatures stubbed, an expired CRL must be reported as
    # expired (previously it surfaced as "ASK certificate is revoked")
    certs = {"ark": builtin_ark(ProcType.GENOA), "ask": builtin_ask(ProcType.GENOA)}
    with (
        patch("sev_pytools.verify.verify_certificate_chain", return_value=True),
        patch("sev_pytools.verify.verify_crl", return_value=True),
    ):
        with pytest.raises(ValueError, match="CRL expired"):
            verify_certificate_chain_with_crl(
                dict(certs, vcek=certs["ask"]),
                crl=_crl(datetime.now(timezone.utc) - timedelta(days=1)),
                processor_model=ProcType.GENOA,
            )


# --------------------------------------------------------------------------- #
# End-to-end decision with the crypto verification mocked
# --------------------------------------------------------------------------- #
FRESH_CRL = _crl(datetime.now(timezone.utc) + timedelta(days=1))

# A stand-in AMD root (RSA-PSS like the real ARK) and VCEKs carrying the SNP
# extensions, so the hypervisor-table checks run on real certificate contents.
TEST_ARK_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def _name(cn):
    return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])


def _test_vcek(hwid=bytes(range(64)), bl=9, tee=0, snp=23, ucode=72):
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("SEV-VCEK"))
        .issuer_name(_name("SEV-Test"))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(SnpOid.HwId.value, hwid), False)
    )
    for oid, value in (
        (SnpOid.BootLoader, bl),
        (SnpOid.Tee, tee),
        (SnpOid.Snp, snp),
        (SnpOid.Ucode, ucode),
    ):  # AMD encodes each TCB component as a DER INTEGER
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid.value, bytes([0x02, 0x01, value])), False
        )
    return builder.sign(key, hashes.SHA384())


TEST_ARK = (
    x509.CertificateBuilder()
    .subject_name(_name("ARK-Test"))
    .issuer_name(_name("ARK-Test"))
    .public_key(TEST_ARK_KEY.public_key())
    .serial_number(1)
    .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
    .sign(TEST_ARK_KEY, hashes.SHA384(), rsa_padding=TEST_PSS)
)
TEST_VCEK = _test_vcek()
ARK_CRL = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(_name("ARK-Test"))
    .last_update(datetime.now(timezone.utc) - timedelta(days=1))
    .next_update(datetime.now(timezone.utc) + timedelta(days=1))
    .sign(TEST_ARK_KEY, hashes.SHA384(), rsa_padding=TEST_PSS)
)


@pytest.fixture
def amd_issued():
    """Treat VCEKs issued to 'SEV-Test' as signed by the built-in ASK under TEST_ARK."""

    def complete(certs):
        if certs["vcek"].issuer != _name("SEV-Test"):
            raise ValueError("The VCEK was not issued by any built-in AMD ASK.")
        return {"ark": TEST_ARK, "ask": TEST_ARK, **certs}

    with (
        patch("sev_pytools.verify_tas.complete_certificates", side_effect=complete),
        patch("sev_pytools.verify_tas.builtin_ark", return_value=TEST_ARK),
    ):
        yield


def test_usable_table_certs(amd_issued, caplog):
    report = AttestationReport.unpack(_report())
    # genuine VCEK for this chip/TCB and an ARK-signed CRL: both used
    assert usable_table_certs(
        {"vcek": TEST_VCEK, "crl": ARK_CRL}, report, ProcType.GENOA
    ) == {"vcek": TEST_VCEK, "crl": ARK_CRL}
    # stale table: VCEK for the previous TCB -> dropped, not a verdict
    assert (
        usable_table_certs({"vcek": _test_vcek(snp=22)}, report, ProcType.GENOA) == {}
    )
    assert "stale certificate table" in caplog.text
    # VCEK for another chip
    assert (
        usable_table_certs({"vcek": _test_vcek(hwid=bytes(64))}, report, ProcType.GENOA)
        == {}
    )
    # not issued by AMD at all
    assert (
        usable_table_certs(
            {"vcek": builtin_ask(ProcType.GENOA)}, report, ProcType.GENOA
        )
        == {}
    )
    assert "not issued by any built-in AMD ASK" in caplog.text
    # CRL not signed by the ARK
    assert usable_table_certs({"crl": FRESH_CRL}, report, ProcType.GENOA) == {}
    assert "CRL: not signed by the AMD ARK" in caplog.text


@pytest.fixture
def verified(server, amd_issued):
    """Patch the signature verification and CRL so the decision logic can be tested alone."""
    with (
        patch(
            "sev_pytools.verify_tas.verify_attestation_bytes",
            side_effect=lambda report_bytes, **k: (
                AttestationReport.unpack(report_bytes),
                k["certificates"],
                "",
            ),
        ) as vab,
        patch("sev_pytools.verify_tas.request_crl_kds", return_value=FRESH_CRL),
        patch("sev_pytools.verify_tas.os.urandom", return_value=NONCE),
    ):
        yield vab


def _serve(server, **overrides):
    """Make the test server answer with a payload built for the posted nonce."""
    server["state"]["payload_overrides"] = overrides


def _auxblob(*entries):
    return base64.b64encode(_table(*entries)).decode()


def test_verify_tas_binds_report_data_and_uses_table_certs(server, verified, tmp_path):
    _serve(
        server,
        auxblob=_auxblob(
            (VCEK_GUID, TEST_VCEK.public_bytes(serialization.Encoding.DER)),
            (CRL_GUID, ARK_CRL.public_bytes(serialization.Encoding.DER)),
        ),
    )
    policy = build_policy(MEASUREMENT)
    with patch("sev_pytools.verify_tas.policy_verify_attestation_report") as pol:
        report = verify_tas(server["url"], policy, certs_dir=str(tmp_path))
    assert report.measurement == bytes(48)
    assert verified.call_args.kwargs["certificates"] == {"vcek": TEST_VCEK}
    assert verified.call_args.kwargs["crl"] == ARK_CRL
    assert pol.call_args.args[1] is policy
    assert pol.call_args.args[2] == expected_report_data(NONCE, server["der"])
    # the verified VCEK is cached per chip and reported TCB for offline reuse
    assert (tmp_path / "0001020304050607-9.0.23.72" / "vcek.pem").exists()


def test_verify_tas_ignores_stale_table_and_uses_kds(server, verified, tmp_path):
    stale = _test_vcek(snp=22)
    _serve(
        server,
        auxblob=_auxblob((VCEK_GUID, stale.public_bytes(serialization.Encoding.DER))),
    )
    with (
        patch("sev_pytools.verify_tas.policy_verify_attestation_report"),
        patch("sev_pytools.verify_tas.request_vcek_kds", return_value=TEST_VCEK) as kds,
    ):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
    kds.assert_called_once()
    assert verified.call_args.kwargs["certificates"] == {"vcek": TEST_VCEK}
    assert verified.call_args.kwargs["crl"] is FRESH_CRL


def test_verify_tas_refetches_corrupt_cached_vcek(server, verified, tmp_path, caplog):
    cached = tmp_path / "0001020304050607-9.0.23.72" / "vcek.pem"
    cached.parent.mkdir()
    cached.write_bytes(b"garbage")
    _serve(server)
    with (
        patch("sev_pytools.verify_tas.policy_verify_attestation_report"),
        patch("sev_pytools.verify_tas.request_vcek_kds", return_value=TEST_VCEK) as kds,
    ):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
    kds.assert_called_once()
    assert "unreadable; fetching again" in caplog.text
    assert x509.load_pem_x509_certificate(cached.read_bytes()) == TEST_VCEK


def test_verify_tas_processor_hint_for_v2_reports(server, verified, tmp_path):
    _serve(server)  # _report() is version 2: no CPUID in the report
    with (
        patch("sev_pytools.verify_tas.policy_verify_attestation_report"),
        patch("sev_pytools.verify_tas.request_vcek_kds", return_value=TEST_VCEK) as kds,
    ):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
        assert kds.call_args.args[0] is ProcType.GENOA
        verify_tas(
            server["url"],
            build_policy(MEASUREMENT),
            certs_dir=str(tmp_path / "milan"),
            processor=ProcType.MILAN,
        )
        assert kds.call_args.args[0] is ProcType.MILAN
    assert verified.call_args.kwargs["processor_model"] == "milan"


def test_verify_tas_uses_cached_vcek_then_kds(server, verified, tmp_path):
    vcek = builtin_ask(ProcType.GENOA)
    _serve(server)
    with (
        patch("sev_pytools.verify_tas.policy_verify_attestation_report"),
        patch("sev_pytools.verify_tas.request_vcek_kds", return_value=vcek) as kds,
    ):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
        assert kds.call_count == 1
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
        assert kds.call_count == 1  # second run served from the cache
        kds.side_effect = Exception("Unable to fetch VCEK: HTTP 429")
        # a different reported TCB is a different VCEK: cache miss, KDS down -> no verdict
        _serve(server, report=base64.b64encode(_report(reported_snp=22)).decode())
        with pytest.raises(TasUndeterminedError, match="KDS"):
            verify_tas(
                server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path)
            )


def test_verify_tas_policy_failure_is_not_trusted(server, verified, tmp_path):
    _serve(server)
    with (
        patch(
            "sev_pytools.verify_tas.request_vcek_kds",
            return_value=builtin_ask(ProcType.GENOA),
        ),
        patch(
            "sev_pytools.verify_tas.policy_verify_attestation_report",
            side_effect=PolicyValidationError("measurement"),
        ),
    ):
        with pytest.raises(TasVerifyError, match="measurement"):
            verify_tas(
                server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path)
            )


def test_verify_tas_rejects_vlek_signed_report(server, verified, tmp_path):
    _serve(server, report=base64.b64encode(_report(signing_key=1)).decode())
    with pytest.raises(TasVerifyError, match="VLEK"):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))


def test_verify_tas_rejects_garbage_report(server, verified, tmp_path):
    _serve(server, report=base64.b64encode(b"short").decode())
    with pytest.raises(TasVerifyError, match="unparsable"):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))


def test_verify_tas_tcb_mismatch_warns_or_fails(server, verified, tmp_path, caplog):
    _serve(server, report=base64.b64encode(_report(current_snp=24)).decode())
    with (
        patch("sev_pytools.verify_tas.policy_verify_attestation_report"),
        patch(
            "sev_pytools.verify_tas.request_vcek_kds",
            return_value=builtin_ask(ProcType.GENOA),
        ),
    ):
        verify_tas(server["url"], build_policy(MEASUREMENT), certs_dir=str(tmp_path))
        assert (
            "Reported TCB 9.0.23.72 differs from the current TCB 9.0.24.72"
            in caplog.text
        )
        with pytest.raises(TasVerifyError, match="differs from the current TCB"):
            verify_tas(
                server["url"],
                build_policy(MEASUREMENT),
                certs_dir=str(tmp_path),
                require_tcb_match=True,
            )


# --------------------------------------------------------------------------- #
# CLI: exit codes and option combination
# --------------------------------------------------------------------------- #
def _run_main(capsys, *argv):
    with patch("sys.argv", ["sev-verify-tas", *argv]):
        code = main()
    return code, capsys.readouterr().out.strip().splitlines()[-1]


def test_main_exit_codes(server, verified, tmp_path, capsys):
    _serve(server)
    args = (server["url"], "-m", MEASUREMENT, "-c", str(tmp_path), "--quiet")
    with patch(
        "sev_pytools.verify_tas.request_vcek_kds",
        return_value=builtin_ask(ProcType.GENOA),
    ):
        with patch("sev_pytools.verify_tas.policy_verify_attestation_report"):
            assert _run_main(capsys, *args) == (
                0,
                f"TRUSTED: {server['url']} is running in a verified AMD SEV-SNP CVM",
            )
        with patch(
            "sev_pytools.verify_tas.policy_verify_attestation_report",
            side_effect=PolicyValidationError("measurement mismatch"),
        ):
            assert _run_main(capsys, *args)[0] == 1
    server["state"].update(status=503, body=b'{"error": "busy"}')
    code, last = _run_main(capsys, *args)
    assert code == 2 and last.startswith("UNDETERMINED:")
    assert (
        _run_main(capsys, "https://127.0.0.1:1", "-m", MEASUREMENT, "--quiet")[0] == 2
    )
    assert (
        _run_main(
            capsys, server["url"], "-m", MEASUREMENT, "--min-tcb", "bogus", "--quiet"
        )[0]
        == 2
    )


def test_main_measurement_overrides_policy_file(
    server, verified, tmp_path, capsys, monkeypatch
):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "metadata": {"name": "t", "version": "1"},
                "validation_rules": {
                    "measurement": {"exact_match": "cd" * 48},
                    "vmpl": {"exact_match": 3},
                },
            }
        )
    )
    _serve(server)
    monkeypatch.setenv("SEV_PYTOOLS_CERTS_DIR", str(tmp_path / "cache"))  # no -c
    with (
        patch(
            "sev_pytools.verify_tas.request_vcek_kds",
            return_value=builtin_ask(ProcType.GENOA),
        ),
        patch("sev_pytools.verify_tas.policy_verify_attestation_report") as pol,
    ):
        code, _ = _run_main(
            capsys,
            server["url"],
            "-q",
            str(policy_file),
            "-m",
            MEASUREMENT,
            "--quiet",
        )
    assert code == 0
    rules = pol.call_args.args[1].policy["validation_rules"]
    assert rules["measurement"] == {"exact_match": MEASUREMENT}  # -m wins
    assert rules["vmpl"] == {"exact_match": 3}  # the rest of the file still applies
    assert (tmp_path / "cache" / "0001020304050607-9.0.23.72" / "vcek.pem").exists()
