from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from hermes_cli import auth


def _stat(uid: int, gid: int):
    return SimpleNamespace(st_uid=uid, st_gid=gid)


def test_root_auth_write_prefers_existing_non_root_file_owner() -> None:
    assert auth._select_auth_store_owner_ids(_stat(1001, 1001), _stat(1002, 1002)) == (
        1001,
        1001,
    )


def test_root_auth_write_repairs_root_owned_file_from_non_root_parent() -> None:
    assert auth._select_auth_store_owner_ids(_stat(0, 0), _stat(1001, 1001)) == (
        1001,
        1001,
    )


def test_root_auth_write_keeps_root_owner_under_root_home() -> None:
    assert auth._select_auth_store_owner_ids(_stat(0, 0), _stat(0, 0)) == (0, 0)


def test_save_auth_store_applies_selected_owner_to_temp_and_final(
    tmp_path,
    monkeypatch,
) -> None:
    auth_path = tmp_path / "auth.json"
    calls: list[tuple[str, tuple[int, int] | None]] = []

    monkeypatch.setattr(auth, "_auth_file_path", lambda: auth_path)
    monkeypatch.setattr(
        auth,
        "_auth_store_owner_ids_for_root_write",
        lambda path: (1001, 1001) if path == auth_path else None,
    )
    monkeypatch.setattr(
        auth,
        "_apply_auth_store_owner",
        lambda path, owner_ids: calls.append((path.name, owner_ids)),
    )

    saved = auth._save_auth_store({"providers": {}})

    assert saved == auth_path
    assert any(
        name.startswith("auth.json.tmp.") and owner_ids == (1001, 1001)
        for name, owner_ids in calls
    )
    assert ("auth.json", (1001, 1001)) in calls
    assert auth_path.exists()


def test_auth_store_lock_repairs_root_created_lock_owner_before_acquire(
    tmp_path,
    monkeypatch,
) -> None:
    auth_path = tmp_path / "auth.json"
    lock_path = auth_path.with_suffix(".lock")
    calls: list[tuple[int, int]] = []

    monkeypatch.setattr(
        auth,
        "_auth_store_owner_ids_for_root_write",
        lambda path: (1001, 1001) if path == lock_path else None,
    )
    monkeypatch.setattr(
        auth.os,
        "fchown",
        lambda fd, uid, gid: calls.append((uid, gid)),
    )

    @contextmanager
    def fake_file_lock(path, holder, timeout_seconds, timeout_message):
        assert path == lock_path
        assert lock_path.is_file()
        assert calls == [(1001, 1001)]
        yield

    monkeypatch.setattr(auth, "_file_lock", fake_file_lock)

    with auth._auth_store_lock(target_path=auth_path):
        pass


def test_auth_store_lock_does_not_follow_symlink(tmp_path, monkeypatch) -> None:
    auth_path = tmp_path / "auth.json"
    target = tmp_path / "unrelated"
    target.write_text("do-not-touch", encoding="utf-8")
    target.chmod(0o644)
    auth_path.with_suffix(".lock").symlink_to(target)

    monkeypatch.setattr(auth.os, "geteuid", lambda: 0)

    with pytest.raises(OSError):
        with auth._auth_store_lock(target_path=auth_path):
            pass

    assert target.read_text(encoding="utf-8") == "do-not-touch"
    assert target.stat().st_mode & 0o777 == 0o644
