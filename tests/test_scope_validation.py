from pathlib import Path

import pytest

from recon_ai.utils.validators import ScopeAuthorizer, normalize_target


def test_scope_validation_exact_wildcard_and_cidr(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "\n".join(
            [
                "example.com",
                "*.example.com",
                "192.168.1.0/24",
            ]
        ),
        encoding="utf-8",
    )
    authorizer = ScopeAuthorizer.from_file(scope_file)
    assert authorizer.is_authorized("example.com")
    assert authorizer.is_authorized("api.example.com")
    assert authorizer.is_authorized("192.168.1.25")
    assert not authorizer.is_authorized("example.org")
    assert not authorizer.is_authorized("192.168.2.10")


def test_scope_validation_rejects_bypass_like_paths(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")
    authorizer = ScopeAuthorizer.from_file(scope_file)
    with pytest.raises(ValueError):
        normalize_target("https://example.com/admin/../../evil")
    assert not authorizer.is_authorized("example.com.evil.org")

