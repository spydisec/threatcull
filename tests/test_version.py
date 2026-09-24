# SPDX-License-Identifier: AGPL-3.0-only
from threatcull import __version__


def test_version_is_semver() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
