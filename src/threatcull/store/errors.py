# SPDX-License-Identifier: AGPL-3.0-only
"""Errors raised by the store."""


class NotFoundError(LookupError):
    """A requested Source, Output or Allowlist entry does not exist."""


class PolicyError(Exception):
    """An operation the current state does not allow (for example, fetching a disabled Source)."""
