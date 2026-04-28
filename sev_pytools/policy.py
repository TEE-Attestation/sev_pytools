# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Policy validation framework for AMD SEV-SNP attestation reports.

import json
import os
from typing import Any, Dict, List, Optional, Union

from .attestation_report import AttestationReport
from .sev_logging import get_logger

logger = get_logger(__name__)


class PolicyValidationError(Exception):
    """Exception raised when policy validation fails."""

    pass


class AttestationPolicy:
    """
    AttestationPolicy - Validates SEV-SNP attestation reports against security policies

    This class loads and validates attestation reports against predefined security policies
    specified in JSON format.
    """

    def __init__(
        self,
        policy_data: Optional[Dict[str, Any]] = None,
        policy_file: Optional[str] = None,
    ):
        """
        Initialize AttestationPolicy from JSON data or file.

        Args:
            policy_data: Dictionary containing policy rules
            policy_file: Path to JSON file containing policy rules

        Raises:
            ValueError: If neither policy_data nor policy_file is provided, or if the policy file is invalid
            FileNotFoundError: If policy_file doesn't exist
            json.JSONDecodeError: If policy file contains invalid JSON
        """
        if policy_data is not None:
            self.policy = policy_data
        elif policy_file is not None:
            self.policy = self._load_policy_file(policy_file)
        else:
            raise ValueError("Either policy_data or policy_file must be provided")

        self._validate_policy_structure()

    def _load_policy_file(self, policy_file: str) -> Dict[str, Any]:
        """Load policy from JSON file."""
        if not os.path.exists(policy_file):
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        with open(policy_file, "r") as f:
            return json.load(f)

    def _validate_policy_structure(self) -> None:
        """Validate that the policy has the expected structure."""
        required_sections = ["metadata", "validation_rules"]
        for section in required_sections:
            if section not in self.policy:
                raise ValueError(f"Policy missing required section: {section}")

    def validate_report(
        self,
        report: AttestationReport,
        report_data: bytes = None,
    ) -> bool:
        """
        Validate an attestation report against the policy.

        Args:
            report: AttestationReport object to validate
            report_data: Optional report data to validate against the report's report_data field

        Returns:
            True if report passes all policy checks

        Raises:
            PolicyValidationError: If any policy check fails
        """
        logger.info(
            f"Validating report against policy: {self.policy.get('metadata', {}).get('name', 'Unknown')}"
        )
        logger.debug(self.get_policy_summary())

        # Validate report_data if provided
        if report_data is not None:
            logger.info("Validating provided report_data against attestation report")

            # Convert report_data to bytes if it's a string (hex format)
            if isinstance(report_data, str):
                try:
                    # Remove any hex prefix and convert to bytes
                    hex_string = self._normalize_hex_string(report_data)
                    report_data_bytes = bytes.fromhex(hex_string)
                except ValueError as e:
                    error_msg = f"Invalid hex string format for report_data: {e}"
                    logger.error(error_msg)
                    raise PolicyValidationError(error_msg)
            else:
                report_data_bytes = report_data

            if report.report_data != report_data_bytes:
                error_msg = f"Report data mismatch: expected {report_data_bytes.hex()}, got {report.report_data.hex()}"
                logger.error(error_msg)
                raise PolicyValidationError(error_msg)
            else:
                logger.info("Report data validation passed")

        failed_validations = []
        rules = self.policy.get("validation_rules", {})

        # Validate each field in the policy rules
        for field_name, field_rules in rules.items():
            logger.info(f"Validating field: {field_name}")

            try:
                # Get the field value from the report
                if not hasattr(report, field_name):
                    logger.error(
                        f"Field '{field_name}' not found in attestation report"
                    )
                    failed_validations.append(field_name)
                else:
                    field_value = getattr(report, field_name)
                    failed_validations.extend(
                        self._validate_object(field_value, field_rules, field_name)
                    )

            except Exception as e:
                logger.error(f"Error validating field '{field_name}': {e}")
                failed_validations.append(field_name)

        # Check if all validations passed
        if failed_validations:
            raise PolicyValidationError(
                f"Policy validation failed for field(s): {', '.join(failed_validations)}"
            )

        logger.info("All policy validations passed successfully!")

        return True

    def _validate_object(
        self, obj: Any, rules: Dict[str, Any], obj_name: str = ""
    ) -> List[str]:
        """
        Validate an object (simple field or nested object) against validation rules.

        Args:
            obj: The object to validate
            rules: Validation rules for this object
            obj_name: Name of the object for verbose output

        Returns:
            List of fully-qualified field paths that failed validation (empty if all passed)
        """
        failed_fields: List[str] = []

        # Handle different types of validation rules
        for rule_type, rule_value in rules.items():
            if rule_type == "exact_match":
                if not self._validate_exact_match(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            elif rule_type == "min_value":
                if not self._validate_min_value(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            elif rule_type == "max_value":
                if not self._validate_max_value(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            elif rule_type == "allow_list":
                if not self._validate_allow_list(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            elif rule_type == "deny_list":
                if not self._validate_deny_list(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            elif rule_type == "boolean":
                if not self._validate_boolean(obj, rule_value, obj_name):
                    failed_fields.append(obj_name)
            else:
                # Handle nested attribute validation - get the attribute and validate it recursively
                if not hasattr(obj, rule_type):
                    logger.error(f"Field '{rule_type}' not found in {obj_name}")
                    failed_fields.append(f"{obj_name}.{rule_type}" if obj_name else rule_type)
                else:
                    attr_value = getattr(obj, rule_type)
                    attr_name = f"{obj_name}.{rule_type}" if obj_name else rule_type

                    # Handle all validation rules recursively
                    if isinstance(rule_value, dict):
                        # Complex validation rules - recurse
                        failed_fields.extend(
                            self._validate_object(attr_value, rule_value, attr_name)
                        )
                    else:
                        # Simple values - wrap them in a rules dict and recurse
                        if isinstance(rule_value, bool):
                            wrapped_rules = {"boolean": rule_value}
                        else:
                            wrapped_rules = {"exact_match": rule_value}
                        failed_fields.extend(
                            self._validate_object(attr_value, wrapped_rules, attr_name)
                        )

        return failed_fields

    def _validate_exact_match(
        self, field_value: Any, expected_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value exactly matches expected value."""
        if isinstance(field_value, bytes):
            # Handle byte fields by converting expected hex string to bytes
            if isinstance(expected_value, str):
                expected_bytes = bytes.fromhex(
                    self._normalize_hex_string(expected_value)
                )
                if field_value != expected_bytes:
                    logger.error(f"{field_name} value mismatch:")
                    logger.error(f"   Expected: {expected_value}")
                    logger.error(f"   Actual:   {field_value.hex()}")
                    return False
            else:
                if field_value != expected_value:
                    logger.error(
                        f"{field_name} value mismatch: {field_value} != {expected_value}"
                    )
                    return False
        else:
            if field_value != expected_value:
                logger.error(
                    f"{field_name} value mismatch: {field_value} != {expected_value}"
                )
                return False

        logger.debug(f"{field_name} exact match validation passed: {field_value}")
        return True

    def _validate_min_value(
        self, field_value: Any, min_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value is >= minimum value."""
        if field_value < min_value:
            logger.error(
                f"{field_name} value {field_value} < required minimum {min_value}"
            )
            return False
        logger.debug(
            f"{field_name} minimum value validation passed: {field_value} >= {min_value}"
        )
        return True

    def _validate_max_value(
        self, field_value: Any, max_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value is <= maximum value."""
        if field_value > max_value:
            logger.error(
                f"{field_name} value {field_value} > allowed maximum {max_value}"
            )
            return False
        logger.debug(
            f"{field_name} maximum value validation passed: {field_value} <= {max_value}"
        )
        return True

    def _validate_allow_list(
        self,
        field_value: Any,
        allowed_values: List[Any],
        field_name: str = "",
    ) -> bool:
        """Validate that field value is in list of allowed values."""
        if field_value not in allowed_values:
            logger.error(
                f"{field_name} value {field_value} not in allow list {allowed_values}"
            )
            return False
        logger.debug(
            f"{field_name} allow list validation passed: {field_value} in {allowed_values}"
        )
        return True

    def _validate_deny_list(
        self,
        field_value: Any,
        denied_values: List[Any],
        field_name: str = "",
    ) -> bool:
        """Validate that field value is not in list of denied values."""
        if field_value in denied_values:
            logger.error(
                f"{field_name} value {field_value} found in deny list {denied_values}"
            )
            return False
        logger.debug(
            f"{field_name} deny list validation passed: {field_value} not in {denied_values}"
        )
        return True

    def _validate_boolean(
        self,
        field_value: Any,
        expected_value: bool,
        field_name: str = "",
    ) -> bool:
        """Validate that field value matches expected boolean value."""
        if field_value != expected_value:
            logger.error(f"{field_name} is {field_value}, expected {expected_value}")
            return False
        logger.debug(f"{field_name} is correctly set to {expected_value}")
        return True

    def _normalize_hex_string(self, hex_str: str) -> str:
        """Normalize hex string by removing prefixes and converting to lowercase."""
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str.lower()

    def get_policy_summary(self) -> str:
        """Get a human-readable summary of the policy."""
        metadata = self.policy.get("metadata", {})
        rules = self.policy.get("validation_rules", {})

        summary = []
        summary.append(f"Policy: {metadata.get('name', 'Unknown')}")
        summary.append(f"Version: {metadata.get('version', 'Unknown')}")
        summary.append(f"Description: {metadata.get('description', 'No description')}")
        summary.append("")
        summary.append("Validation Rules:")

        self._format_rules_summary(rules, summary, "  ")

        return "\n".join(summary)

    def _format_rules_summary(
        self, rules: Dict[str, Any], summary: List[str], indent: str
    ) -> None:
        """Recursively format validation rules for the summary."""
        for field_name, field_rules in rules.items():
            if isinstance(field_rules, dict):
                summary.append(f"{indent}- {field_name}:")
                for rule_type, rule_value in field_rules.items():
                    if rule_type in [
                        "exact_match",
                        "min_value",
                        "max_value",
                        "allow_list",
                        "deny_list",
                        "boolean",
                    ]:
                        summary.append(f"{indent}  • {rule_type}: {rule_value}")
                    elif isinstance(rule_value, dict):
                        summary.append(f"{indent}  • {rule_type}:")
                        self._format_rules_summary(rule_value, summary, indent + "    ")
                    else:
                        summary.append(f"{indent}  • {rule_type}: {rule_value}")
            else:
                summary.append(f"{indent}- {field_name}: {field_rules}")


def validate_report_with_policy(
    report: AttestationReport,
    policy_file: str,
    report_data: bytes = None,
) -> bool:
    """
    Convenience function to validate a report against a policy file.

    Args:
        report: AttestationReport object to validate
        policy_file: Path to JSON policy file
        report_data: Optional report data to validate against

    Returns:
        True if report passes all policy checks

    Raises:
        PolicyValidationError: If any policy check fails
    """
    policy = AttestationPolicy(policy_file=policy_file)
    return policy.validate_report(report, report_data=report_data)
