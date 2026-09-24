# SPDX-License-Identifier: AGPL-3.0-only
"""Errors raised by the store."""


class NotFoundError(LookupError):
    """A requested Source, Output or Allowlist entry does not exist."""


class PolicyError(Exception):
    """An operation would break Business Mode or needs an explicit acknowledgement."""
