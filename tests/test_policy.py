# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Tests for sev_pytools.policy: AttestationPolicy loading, rule evaluation,
# nested-field handling and the validate_report_with_policy helper.
#
# The fixture report is a genuine Milan SEV-SNP attestation report (attestation
# reports carry no secrets; they are designed to be handed to untrusted
# verifiers). Values asserted below are read from it in ``_fixture_values``.

import json
from pathlib import Path

import pytest

from sev_pytools import (
    AttestationPolicy,
    AttestationReport,
    PolicyValidationError,
    validate_report_with_policy,
)

REPORT_PATH = Path(__file__).parent / "data" / "milan_report.bin"

# Byte-field values carried by the fixture report, as lowercase hex.
MEASUREMENT_HEX = (
    "e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c"
    "8d5d30fcad5f4f0e04f1a13885eb984d"
)
HOST_DATA_HEX = "00" * 32
OTHER_48_HEX = "ab" * 48


@pytest.fixture(scope="module")
def report() -> AttestationReport:
    return AttestationReport.unpack(REPORT_PATH.read_bytes())


@pytest.fixture(autouse=True, scope="module")
def _fixture_values(report):
    """Pin the fixture values the tests below rely on; update if the file changes."""
    assert report.measurement.hex() == MEASUREMENT_HEX
    assert report.host_data.hex() == HOST_DATA_HEX
    assert report.vmpl == 0
    assert report.signature_algo == 1
    assert report.version == 5
    assert (
        report.current_tcb.bootloader,
        report.current_tcb.tee,
        report.current_tcb.snp,
        report.current_tcb.microcode,
    ) == (4, 0, 29, 222)
    assert report.policy.debug_allowed is False
    assert report.policy.smt_allowed is True
    assert report.platform_info.smt_enabled is True
    assert report.platform_info.tsme_enabled is False
    assert (report.cpuid.family_id, report.cpuid.model_id) == (0x19, 0x01)


def _policy(rules: dict, **metadata) -> AttestationPolicy:
    """Build a policy from a validation_rules dict."""
    return AttestationPolicy(
        policy_data={
            "metadata": {"name": "test policy", **metadata},
            "validation_rules": rules,
        }
    )


def _passes(report, rules: dict) -> bool:
    return _policy(rules).validate_report(report) is True


def _fails_on(report, rules: dict, *fields: str):
    """Assert validation fails and every named field appears in the error."""
    with pytest.raises(PolicyValidationError) as exc:
        _policy(rules).validate_report(report)
    message = str(exc.value)
    assert message.startswith("Policy validation failed for field(s):")
    for field in fields:
        assert field in message, f"{field!r} not in {message!r}"
    return message


# ── Construction and loading ─────────────────────────────────────────────────


class TestConstruction:
    def test_requires_data_or_file(self):
        with pytest.raises(ValueError, match="Either policy_data or policy_file"):
            AttestationPolicy()

    def test_from_data(self):
        policy = _policy({})
        assert policy.policy["metadata"]["name"] == "test policy"

    def test_from_file(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text(
            json.dumps(
                {
                    "metadata": {"name": "f"},
                    "validation_rules": {"vmpl": {"exact_match": 0}},
                }
            )
        )
        policy = AttestationPolicy(policy_file=str(path))
        assert policy.policy["metadata"]["name"] == "f"

    def test_data_takes_precedence_over_file(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text(
            json.dumps({"metadata": {"name": "file"}, "validation_rules": {}})
        )
        policy = AttestationPolicy(
            policy_data={"metadata": {"name": "data"}, "validation_rules": {}},
            policy_file=str(path),
        )
        assert policy.policy["metadata"]["name"] == "data"

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            AttestationPolicy(policy_file=str(tmp_path / "nope.json"))

    def test_invalid_json_file(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(json.JSONDecodeError):
            AttestationPolicy(policy_file=str(path))

    @pytest.mark.parametrize("missing", ["metadata", "validation_rules"])
    def test_required_sections(self, missing):
        data = {"metadata": {}, "validation_rules": {}}
        del data[missing]
        with pytest.raises(ValueError, match=f"missing required section: {missing}"):
            AttestationPolicy(policy_data=data)

    def test_empty_rules_pass(self, report):
        assert _passes(report, {})

    def test_summary_mentions_metadata_and_rules(self):
        policy = _policy(
            {"vmpl": {"exact_match": 0}, "current_tcb": {"snp": {"min_value": 1}}},
            version="9.9",
            description="desc",
        )
        summary = policy.get_policy_summary()
        assert "test policy" in summary
        assert "9.9" in summary
        assert "desc" in summary
        assert "vmpl" in summary
        assert "snp" in summary


# ── exact_match ──────────────────────────────────────────────────────────────


class TestExactMatch:
    def test_integer_pass(self, report):
        assert _passes(report, {"vmpl": {"exact_match": 0}})

    def test_integer_fail(self, report):
        _fails_on(report, {"vmpl": {"exact_match": 3}}, "vmpl")

    def test_bare_value_is_exact_match_nested(self, report):
        """A non-dict, non-bool rule value is shorthand for exact_match."""
        assert _passes(report, {"current_tcb": {"snp": 29}})
        _fails_on(report, {"current_tcb": {"snp": 30}}, "current_tcb.snp")

    def test_bare_value_is_exact_match_top_level(self, report):
        """The shorthand must also work for top-level report fields.

        Regression test: top-level bare values were once passed straight to
        _validate_object (which expects a dict), so they could never pass.
        """
        assert _passes(report, {"vmpl": 0})
        _fails_on(report, {"vmpl": 3}, "vmpl")

    def test_bytes_pass(self, report):
        assert _passes(report, {"measurement": {"exact_match": MEASUREMENT_HEX}})

    def test_bytes_fail(self, report):
        _fails_on(report, {"measurement": {"exact_match": OTHER_48_HEX}}, "measurement")

    @pytest.mark.parametrize(
        "variant",
        [
            MEASUREMENT_HEX.upper(),
            "0x" + MEASUREMENT_HEX,
            "0x" + MEASUREMENT_HEX.upper(),
        ],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_bytes_hex_normalisation(self, report, variant):
        assert _passes(report, {"measurement": {"exact_match": variant}})

    def test_bytes_bare_value_shorthand(self, report):
        """Top-level byte-field shorthand (see test_bare_value_is_exact_match_top_level)."""
        assert _passes(report, {"measurement": MEASUREMENT_HEX})
        _fails_on(report, {"measurement": OTHER_48_HEX}, "measurement")

    def test_bytes_wrong_length_hex_fails(self, report):
        _fails_on(report, {"measurement": {"exact_match": "aabb"}}, "measurement")

    def test_bytes_invalid_hex_fails_not_raises(self, report):
        """Malformed policy hex is reported as a failed field, not an exception."""
        _fails_on(report, {"measurement": {"exact_match": "zz" * 48}}, "measurement")

    def test_bytes_against_bytes_value(self, report):
        """Programmatic policies may supply bytes directly."""
        assert _passes(report, {"measurement": {"exact_match": report.measurement}})
        _fails_on(report, {"measurement": {"exact_match": b"\xab" * 48}}, "measurement")


# ── min_value / max_value ────────────────────────────────────────────────────


class TestRangeRules:
    @pytest.mark.parametrize("rule, bound", [("min_value", 0), ("min_value", 29)])
    def test_min_pass(self, report, rule, bound):
        assert _passes(report, {"current_tcb": {"snp": {rule: bound}}})

    def test_min_fail(self, report):
        _fails_on(
            report, {"current_tcb": {"snp": {"min_value": 30}}}, "current_tcb.snp"
        )

    @pytest.mark.parametrize("bound", [29, 255])
    def test_max_pass(self, report, bound):
        assert _passes(report, {"current_tcb": {"snp": {"max_value": bound}}})

    def test_max_fail(self, report):
        _fails_on(
            report, {"current_tcb": {"snp": {"max_value": 28}}}, "current_tcb.snp"
        )

    def test_min_and_max_together(self, report):
        assert _passes(report, {"version": {"min_value": 3, "max_value": 5}})
        _fails_on(report, {"version": {"min_value": 3, "max_value": 4}}, "version")

    def test_min_on_top_level_field(self, report):
        assert _passes(report, {"version": {"min_value": 5}})
        _fails_on(report, {"version": {"min_value": 6}}, "version")


# ── boolean ──────────────────────────────────────────────────────────────────


class TestBoolean:
    def test_explicit_boolean_rule(self, report):
        assert _passes(report, {"policy": {"debug_allowed": {"boolean": False}}})
        _fails_on(
            report,
            {"policy": {"debug_allowed": {"boolean": True}}},
            "policy.debug_allowed",
        )

    def test_bare_bool_is_boolean_rule(self, report):
        """A bare true/false rule value is shorthand for {"boolean": ...}."""
        assert _passes(
            report, {"policy": {"debug_allowed": False, "smt_allowed": True}}
        )
        _fails_on(report, {"policy": {"smt_allowed": False}}, "policy.smt_allowed")

    def test_platform_info_flags(self, report):
        assert _passes(
            report,
            {"platform_info": {"smt_enabled": True, "tsme_enabled": False}},
        )
        _fails_on(
            report,
            {"platform_info": {"tsme_enabled": True}},
            "platform_info.tsme_enabled",
        )

    def test_bool_rule_routes_to_boolean_validator(self, report):
        """A bare bool must route to the boolean validator, not exact_match.

        Under exact_match, ``0 == False`` would make ``{"vmpl": False}`` pass;
        the boolean validator compares with ``!=`` too, so observable behaviour
        is identical today. Pin the nested form, which is the documented one.
        """
        assert _passes(report, {"policy": {"debug_allowed": False}})
        _fails_on(report, {"policy": {"debug_allowed": True}}, "policy.debug_allowed")


# ── allow_list / deny_list on scalar fields ──────────────────────────────────


class TestScalarLists:
    def test_allow_pass(self, report):
        assert _passes(report, {"signature_algo": {"allow_list": [1, 2]}})

    def test_allow_fail(self, report):
        _fails_on(report, {"signature_algo": {"allow_list": [2, 3]}}, "signature_algo")

    def test_allow_empty_fails(self, report):
        _fails_on(report, {"signature_algo": {"allow_list": []}}, "signature_algo")

    def test_deny_pass(self, report):
        assert _passes(report, {"signature_algo": {"deny_list": [2, 3]}})

    def test_deny_fail(self, report):
        _fails_on(report, {"signature_algo": {"deny_list": [1]}}, "signature_algo")

    def test_deny_empty_passes(self, report):
        assert _passes(report, {"signature_algo": {"deny_list": []}})

    def test_nested_scalar_lists(self, report):
        assert _passes(
            report, {"cpuid": {"model_id": {"allow_list": [0x00, 0x01, 0x08]}}}
        )
        _fails_on(
            report, {"cpuid": {"model_id": {"deny_list": [0x01]}}}, "cpuid.model_id"
        )


# ── allow_list / deny_list on byte fields ────────────────────────────────────


class TestByteFieldLists:
    """Hex entries in a list must be compared the same way exact_match compares
    a hex string: normalised and decoded to bytes before the membership test.

    Regression tests: the lists were once compared without decoding, so for
    byte fields an allow_list rejected every value and a deny_list allowed
    every value.
    """

    def test_allow_accepts_listed(self, report):
        assert _passes(
            report, {"measurement": {"allow_list": [OTHER_48_HEX, MEASUREMENT_HEX]}}
        )

    def test_allow_rejects_unlisted(self, report):
        _fails_on(
            report, {"measurement": {"allow_list": [OTHER_48_HEX]}}, "measurement"
        )

    def test_allow_empty_fails(self, report):
        _fails_on(report, {"measurement": {"allow_list": []}}, "measurement")

    @pytest.mark.parametrize(
        "variant",
        [
            MEASUREMENT_HEX.upper(),
            "0x" + MEASUREMENT_HEX,
            "0x" + MEASUREMENT_HEX.upper(),
        ],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_allow_hex_normalisation(self, report, variant):
        assert _passes(report, {"measurement": {"allow_list": [variant]}})

    def test_deny_rejects_listed(self, report):
        _fails_on(
            report,
            {"measurement": {"deny_list": [OTHER_48_HEX, MEASUREMENT_HEX]}},
            "measurement",
        )

    def test_deny_accepts_unlisted(self, report):
        assert _passes(report, {"measurement": {"deny_list": [OTHER_48_HEX]}})

    def test_deny_empty_passes(self, report):
        assert _passes(report, {"measurement": {"deny_list": []}})

    @pytest.mark.parametrize(
        "variant",
        [
            MEASUREMENT_HEX.upper(),
            "0x" + MEASUREMENT_HEX,
            "0x" + MEASUREMENT_HEX.upper(),
        ],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_deny_hex_normalisation(self, report, variant):
        _fails_on(report, {"measurement": {"deny_list": [variant]}}, "measurement")

    def test_lists_accept_bytes_entries(self, report):
        """Programmatic policies may supply bytes directly, as exact_match allows."""
        assert _passes(report, {"measurement": {"allow_list": [report.measurement]}})
        _fails_on(
            report, {"measurement": {"deny_list": [report.measurement]}}, "measurement"
        )

    def test_invalid_hex_entry_fails_not_raises(self, report):
        _fails_on(report, {"measurement": {"allow_list": ["zz" * 48]}}, "measurement")
        _fails_on(report, {"measurement": {"deny_list": ["zz" * 48]}}, "measurement")

    def test_other_byte_fields(self, report):
        assert _passes(report, {"host_data": {"allow_list": [HOST_DATA_HEX]}})
        _fails_on(report, {"host_data": {"deny_list": [HOST_DATA_HEX]}}, "host_data")

    def test_single_entry_allow_list_agrees_with_exact_match(self, report):
        for hex_value, expected in ((MEASUREMENT_HEX, True), (OTHER_48_HEX, False)):
            exact = _policy({"measurement": {"exact_match": hex_value}})
            allow = _policy({"measurement": {"allow_list": [hex_value]}})
            if expected:
                assert exact.validate_report(report) and allow.validate_report(report)
            else:
                with pytest.raises(PolicyValidationError):
                    exact.validate_report(report)
                with pytest.raises(PolicyValidationError):
                    allow.validate_report(report)


# ── Nested fields and error reporting ────────────────────────────────────────


class TestNestedFields:
    def test_multiple_nested_rules(self, report):
        assert _passes(
            report,
            {
                "current_tcb": {
                    "bootloader": {"min_value": 4},
                    "tee": {"min_value": 0},
                    "snp": {"min_value": 29},
                    "microcode": {"min_value": 222},
                }
            },
        )

    def test_nested_failure_path_is_dotted(self, report):
        message = _fails_on(
            report,
            {"current_tcb": {"microcode": {"min_value": 223}}},
            "current_tcb.microcode",
        )
        assert "current_tcb.microcode" in message

    def test_unknown_top_level_field_fails(self, report):
        _fails_on(report, {"not_a_field": {"exact_match": 1}}, "not_a_field")

    def test_unknown_nested_field_fails(self, report):
        _fails_on(
            report,
            {"current_tcb": {"not_a_field": {"min_value": 1}}},
            "current_tcb.not_a_field",
        )

    def test_all_failures_reported_together(self, report):
        message = _fails_on(
            report,
            {
                "vmpl": {"exact_match": 3},
                "signature_algo": {"allow_list": [9]},
                "current_tcb": {"snp": {"min_value": 99}},
                "policy": {"debug_allowed": True},
            },
            "vmpl",
            "signature_algo",
            "current_tcb.snp",
            "policy.debug_allowed",
        )
        assert message.count(",") >= 3

    def test_passing_rules_are_not_reported(self, report):
        message = _fails_on(
            report,
            {"vmpl": {"exact_match": 0}, "signature_algo": {"exact_match": 9}},
            "signature_algo",
        )
        assert "vmpl" not in message

    def test_unknown_rule_type_on_scalar_fails(self, report):
        """An unrecognised rule key is treated as a nested attribute lookup."""
        _fails_on(report, {"vmpl": {"not_a_rule": 1}}, "vmpl.not_a_rule")


# ── report_data binding ──────────────────────────────────────────────────────


class TestReportData:
    def test_matching_bytes(self, report):
        assert _policy({}).validate_report(report, report_data=report.report_data)

    def test_matching_hex(self, report):
        hex_value = report.report_data.hex()
        assert _policy({}).validate_report(report, report_data=hex_value)
        assert _policy({}).validate_report(report, report_data="0x" + hex_value.upper())

    def test_mismatch_bytes(self, report):
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({}).validate_report(report, report_data=b"\x00" * 64)

    def test_mismatch_hex(self, report):
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({}).validate_report(report, report_data="00" * 64)

    def test_invalid_hex(self, report):
        with pytest.raises(PolicyValidationError, match="Invalid hex string"):
            _policy({}).validate_report(report, report_data="zz" * 64)

    def test_report_data_checked_before_rules(self, report):
        """A report_data mismatch is raised even if the rules would also fail."""
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({"vmpl": 3}).validate_report(report, report_data=b"\x00" * 64)

    def test_none_skips_check(self, report):
        assert _policy({}).validate_report(report, report_data=None)


# ── validate_report_with_policy helper ───────────────────────────────────────


class TestHelper:
    def _write(self, tmp_path, rules):
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps({"metadata": {"name": "h"}, "validation_rules": rules})
        )
        return str(path)

    def test_pass(self, report, tmp_path):
        path = self._write(tmp_path, {"vmpl": {"exact_match": 0}})
        assert validate_report_with_policy(report, path)

    def test_fail(self, report, tmp_path):
        path = self._write(tmp_path, {"vmpl": {"exact_match": 3}})
        with pytest.raises(PolicyValidationError):
            validate_report_with_policy(report, path)

    def test_report_data_forwarded(self, report, tmp_path):
        path = self._write(tmp_path, {})
        assert validate_report_with_policy(report, path, report_data=report.report_data)
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            validate_report_with_policy(report, path, report_data=b"\x00" * 64)


# ── Example policy shipped in the repo ───────────────────────────────────────


class TestExamplePolicy:
    """The repository's example_policy.json must at least load and evaluate."""

    EXAMPLE = Path(__file__).parent.parent / "example_policy.json"

    def test_loads(self):
        policy = AttestationPolicy(policy_file=str(self.EXAMPLE))
        assert "validation_rules" in policy.policy

    def test_evaluates_without_error(self, report):
        policy = AttestationPolicy(policy_file=str(self.EXAMPLE))
        try:
            policy.validate_report(report)
        except PolicyValidationError:
            # The example pins values for a different machine; failing is fine,
            # raising anything else is not.
            pass
