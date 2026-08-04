"""Hermes installer filesystem safety."""

from __future__ import annotations

import stat

import pytest

import panoptes.install_hermes_plugin as installer


def test_installer_writes_private_files_atomically(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "plugins" / "panoptes"
    monkeypatch.setattr(installer, "get_plugin_dir", lambda: plugin_dir)

    assert installer.install()
    assert stat.S_IMODE(plugin_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((plugin_dir / "manifest.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((plugin_dir / "plugin.py").stat().st_mode) == 0o600
    assert "authorize_tool_call" in (plugin_dir / "plugin.py").read_text(
        encoding="utf-8"
    )

    # A repeat install replaces complete files without leaving temporary data.
    assert installer.install()
    assert list(plugin_dir.glob(".*.json.*")) == []
    assert list(plugin_dir.glob(".*.py.*")) == []


def test_installer_rejects_symlink_plugin_directory(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    plugin_dir = tmp_path / "panoptes"
    plugin_dir.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(installer, "get_plugin_dir", lambda: plugin_dir)

    with pytest.raises(RuntimeError, match="symlink"):
        installer.install()
    with pytest.raises(RuntimeError, match="symlink"):
        installer.uninstall()


def test_installer_rejects_symlink_plugin_file(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "panoptes"
    plugin_dir.mkdir()
    target = tmp_path / "outside.py"
    target.write_text("do not replace", encoding="utf-8")
    (plugin_dir / "plugin.py").symlink_to(target)
    monkeypatch.setattr(installer, "get_plugin_dir", lambda: plugin_dir)

    with pytest.raises(RuntimeError, match="symlink"):
        installer.install()
    assert target.read_text(encoding="utf-8") == "do not replace"
