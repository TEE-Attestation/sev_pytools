# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Tests for the built-in AMD ARK/ASK certificates and ARK pinning.

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sev_pytools import ProcType
from sev_pytools import certs as certs_module
from sev_pytools import load_certificates, verify_certificate_chain
from sev_pytools.builtin_certs import (
    builtin_ark,
    builtin_ask,
    builtin_ca,
    builtin_chains,
    builtin_family_of_ark,
    is_builtin_ark,
)
from sev_pytools.certs import complete_certificates, verify_certificate

# One chain per KDS family; Bergamo and Siena use Genoa's.
FAMILY_MODELS = [
    ("Milan", ProcType.MILAN),
    ("Genoa", ProcType.GENOA),
    ("Turin", ProcType.TURIN),
]

# SHA-256 fingerprints as served by https://kdsintf.amd.com/vcek/v1/<Family>/cert_chain
FINGERPRINTS = {
    "Milan": {
        "ark": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
        "ask": "67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b",
    },
    "Genoa": {
        "ark": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
        "ask": "5464738c1546aed5f2cecf1dc98c5c960a92e8913238a61711bc90ec6e828521",
    },
    "Turin": {
        "ark": "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
        "ask": "5b77ef5fe7a7a004fd9032668fba9d0fda22f88c4442069a479636a6ae3b3185",
    },
}


@pytest.mark.parametrize("family, model", FAMILY_MODELS)
def test_fingerprints_match_amd_kds(family, model):
    for cert_type, getter in (("ark", builtin_ark), ("ask", builtin_ask)):
        fp = getter(model).fingerprint(hashes.SHA256()).hex()
        assert (
            fp == FINGERPRINTS[family][cert_type]
        ), f"{family} {cert_type} fingerprint changed"


@pytest.mark.parametrize("family, model", FAMILY_MODELS)
def test_chain_and_subjects(family, model):
    ark, ask = builtin_ark(model), builtin_ask(model)
    assert verify_certificate(ark, ark.public_key()), "ARK must be self-signed"
    assert verify_certificate(ask, ark.public_key()), "ASK must be signed by the ARK"
    cn = x509.NameOID.COMMON_NAME
    assert ark.subject.get_attributes_for_oid(cn)[0].value == f"ARK-{family}"
    assert ask.subject.get_attributes_for_oid(cn)[0].value == f"SEV-{family}"
    assert builtin_family_of_ark(ark) == family


@pytest.mark.parametrize(
    "model, chain_model",
    [
        (ProcType.BERGAMO, ProcType.GENOA),
        (ProcType.SIENA, ProcType.GENOA),
        ("genoa", ProcType.GENOA),  # ProcType member name is accepted too
        ("Turin", ProcType.TURIN),
    ],
)
def test_model_maps_to_chain(model, chain_model):
    assert builtin_ca(model)["ark"] is builtin_ark(chain_model)
    assert builtin_ca(model)["ask"] is builtin_ask(chain_model)


def test_unknown_model_rejected():
    with pytest.raises(ValueError, match="Unknown processor model"):
        builtin_ca("Naples")


def test_ark_pinning():
    genoa = builtin_ark(ProcType.GENOA)
    assert is_builtin_ark(genoa, ProcType.GENOA)
    assert is_builtin_ark(genoa, ProcType.BERGAMO)
    assert is_builtin_ark(genoa)  # any family
    assert not is_builtin_ark(genoa, ProcType.MILAN)
    assert not is_builtin_ark(builtin_ask(ProcType.GENOA))  # an ASK is not a root


def _make_cert(cn, issuer_cn, signing_key, public_key):
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    name = lambda c: x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, c)])
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(name(issuer_cn))
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(signing_key, hashes.SHA256())
    )


def _self_signed_rsa_cert(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _make_cert(cn, cn, key, key.public_key())


@pytest.fixture(scope="module")
def synthetic_chain():
    """A complete ARK -> ASK -> VCEK chain with keys we control (RSA-2048 for speed)."""
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ark = _make_cert("ARK-Test", "ARK-Test", ark_key, ark_key.public_key())
    ask = _make_cert("SEV-Test", "ARK-Test", ark_key, ask_key.public_key())
    vcek = _make_cert("SEV-VCEK", "SEV-Test", ask_key, vcek_key.public_key())
    return {"ark": ark, "ask": ask, "vcek": vcek}


@pytest.fixture
def with_test_family(monkeypatch, synthetic_chain):
    """Expose the synthetic chain as an extra built-in family, after the real ones."""
    chains = dict(builtin_chains())
    chains["Test"] = {"ark": synthetic_chain["ark"], "ask": synthetic_chain["ask"]}
    monkeypatch.setattr(certs_module, "builtin_chains", lambda: chains)
    monkeypatch.setattr(
        certs_module,
        "builtin_family_of_ark",
        lambda c: "Test" if c == synthetic_chain["ark"] else builtin_family_of_ark(c),
    )
    return synthetic_chain


def test_chain_rejects_rogue_self_signed_ark():
    rogue = _self_signed_rsa_cert("ARK-Genoa")
    ask = builtin_ask(ProcType.GENOA)
    certs = {"ark": rogue, "ask": ask, "vcek": ask}
    assert not is_builtin_ark(rogue)
    with pytest.raises(ValueError, match="not the built-in AMD root"):
        verify_certificate_chain(certs, ProcType.GENOA)


def test_complete_certificates_by_processor_model():
    vcek = builtin_ask(ProcType.GENOA)  # any cert will do when the family is given
    certs = complete_certificates({"vcek": vcek}, ProcType.BERGAMO)
    assert certs["ark"] is builtin_ark(ProcType.GENOA)
    assert certs["ask"] is builtin_ask(ProcType.GENOA)
    assert certs["vcek"] is vcek


def test_complete_certificates_keeps_provided_and_requires_vcek():
    provided = {"ark": "A", "ask": "S", "vcek": "V"}
    assert complete_certificates(provided) == provided
    with pytest.raises(ValueError, match="VCEK"):
        complete_certificates({"ark": builtin_ark(ProcType.MILAN)})


def test_complete_certificates_tries_each_builtin(with_test_family):
    # No processor model: the chain whose ASK signed the VCEK is selected,
    # after the real Milan/Genoa/Turin chains have been tried and rejected.
    certs = complete_certificates({"vcek": with_test_family["vcek"]})
    assert certs["ark"] is with_test_family["ark"]
    assert certs["ask"] is with_test_family["ask"]


def test_complete_certificates_no_builtin_issuer(synthetic_chain):
    with pytest.raises(ValueError, match="not issued by any built-in AMD ASK"):
        complete_certificates({"vcek": synthetic_chain["vcek"]})


def test_chain_verifies_with_only_vcek_provided(with_test_family):
    # verify_certificate_chain fills ARK/ASK itself; pin_ark=False because the
    # synthetic root is not one of the embedded AMD roots.
    assert verify_certificate_chain({"vcek": with_test_family["vcek"]}, pin_ark=False)


def test_load_certificates_fills_ca_from_builtin(tmp_path, with_test_family):
    (tmp_path / "vcek.pem").write_bytes(
        with_test_family["vcek"].public_bytes(serialization.Encoding.PEM)
    )
    certs = load_certificates(str(tmp_path))  # family found by trying each chain
    assert certs["ark"] is with_test_family["ark"]
    assert certs["ask"] is with_test_family["ask"]

    certs = load_certificates(str(tmp_path), ProcType.GENOA)  # explicit family wins
    assert certs["ark"] is builtin_ark(ProcType.GENOA)
    assert certs["ask"] is builtin_ask(ProcType.GENOA)


def test_load_certificates_requires_vcek(tmp_path):
    (tmp_path / "ark.pem").write_bytes(
        builtin_ark(ProcType.GENOA).public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(ValueError, match="Missing required certificates: VCEK"):
        load_certificates(str(tmp_path))
