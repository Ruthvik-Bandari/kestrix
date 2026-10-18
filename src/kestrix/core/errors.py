# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Reason codes and the single rejection exception shared by every module."""

from enum import StrEnum


class Reason(StrEnum):
    # Input safety
    INPUT_TOO_LARGE = "input_too_large"
    MALFORMED_YAML = "malformed_yaml"
    YAML_ALIAS = "yaml_alias_not_allowed"
    YAML_TAG = "yaml_tag_not_allowed"
    NESTING_TOO_DEEP = "nesting_too_deep"
    MALFORMED_JSONL = "malformed_jsonl"
    # Rule structure
    INVALID_RULE = "invalid_rule"
    UNSUPPORTED_LOGSOURCE = "unsupported_logsource"
    UNSUPPORTED_RULE_TYPE = "unsupported_rule_type"
    UNSUPPORTED_SELECTION_FORM = "unsupported_selection_form"
    UNSUPPORTED_MODIFIER = "unsupported_modifier"
    UNSUPPORTED_VALUE = "unsupported_value"
    UNSUPPORTED_WILDCARD = "unsupported_wildcard"
    UNSUPPORTED_CONDITION = "unsupported_condition"
    UNKNOWN_FIELD = "unknown_field"
    UNDEFINED_SELECTION = "undefined_selection"
    # Fixtures and mapping
    INVALID_FIXTURE = "invalid_fixture"
    INVALID_MAPPING = "invalid_mapping"
    # Engine
    ENGINE_UNAVAILABLE = "engine_unavailable"
    ENGINE_ERROR = "engine_error"
    INDEX_COUNT_MISMATCH = "index_count_mismatch"
    CONVERSION_FAILED = "conversion_failed"
    # Candidates
    INVALID_CANDIDATE = "invalid_candidate"
    # Network targets and external services
    INVALID_URL = "invalid_url"
    TARGET_NOT_ALLOWED = "target_not_allowed"
    TARGET_UNREACHABLE = "target_unreachable"
    UPSTREAM_ERROR = "upstream_error"
    AI_KEY_MISSING = "ai_key_missing"
    # Generic validated input
    INVALID_INPUT = "invalid_input"


class Rejected(Exception):
    """Raised when an input or candidate falls outside the supported contract."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail
