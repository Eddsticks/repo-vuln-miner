"""Integración local con Git real: persistencia, reutilización y manifiesto."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import RepositoryCloneError, RepositoryWorkspace


def git(path: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=Miner tests", "-c", "user.email=miner@example.test",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
         "-C", str(path), *arguments],
        check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> GitHubRepository:
    origin = tmp_path / "origin with spaces"
    origin.mkdir()
    git(origin, "init", "--initial-branch=main")
    (origin / "package.json").write_text('{"name":"example","version":"1.0.0"}\n')
    (origin / ".gitignore").write_text("ignored.txt\n")
    git(origin, "add", ".")
    git(origin, "commit", "-m", "Initial fixture")
    return GitHubRepository(
        owner="example", name="app", default_branch="main",
        url="https://github.com/example/app", clone_url=origin.as_uri(),
    )


def test_clone_survives_and_can_be_opened_offline(tmp_path: Path, repository: GitHubRepository) -> None:
    repos = tmp_path / "persistent clones"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        cloned = workspace.clone(repository)
        artifacts = workspace.root
        (artifacts / "database").mkdir()
        original_sha = cloned.commit_sha

    assert cloned.source_path.is_dir()
    assert not artifacts.exists()
    manifest = RepositoryWorkspace(repos_directory=repos).read_manifest()
    assert manifest.schema_version == 1
    assert manifest.repositories[0].relative_path == "example/app"
    assert manifest.repositories[0].commit_sha == original_sha

    calls: list[list[str]] = []

    def offline_runner(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        assert not {"clone", "fetch", "pull"}.intersection(command)
        calls.append(command)
        return subprocess.run(command, **kwargs)

    with RepositoryWorkspace(repos_directory=repos, runner=offline_runner) as workspace:
        reopened = workspace.open_registered("example", "app")
        assert reopened.commit_sha == original_sha
        assert reopened.source_path == cloned.source_path
        assert reopened.repository.url == repository.url
    assert calls


def test_reuse_reads_current_head_and_retains_registered_branch(
    tmp_path: Path, repository: GitHubRepository,
) -> None:
    repos = tmp_path / "repos"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        cloned = workspace.clone(repository)
    git(cloned.source_path, "commit", "--allow-empty", "-m", "New local revision")
    expected_sha = git(cloned.source_path, "rev-parse", "HEAD")
    changed_metadata = repository.model_copy(update={"default_branch": "renamed-upstream"})
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        reused = workspace.clone(changed_metadata)
        assert reused.commit_sha == expected_sha != cloned.commit_sha
        entry = workspace.read_manifest().repositories[0]
        assert entry.commit_sha == expected_sha
        assert entry.default_branch == "main"


@pytest.mark.parametrize("change", ["tracked", "staged", "untracked", "ignored"])
def test_reuse_rejects_changes_without_overwriting_them(
    tmp_path: Path, repository: GitHubRepository, change: str,
) -> None:
    repos = tmp_path / "repos"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        cloned = workspace.clone(repository)
    manifest_before = (repos / "manifest.json").read_bytes()
    name = {"tracked": "package.json", "staged": "package.json",
            "untracked": "extra.txt", "ignored": "ignored.txt"}[change]
    changed_file = cloned.source_path / name
    changed_file.write_text("local changes")
    if change == "staged":
        git(cloned.source_path, "add", name)
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="local changes or additional files"):
            workspace.open_registered("example", "app")
    assert changed_file.read_text() == "local changes"
    assert (repos / "manifest.json").read_bytes() == manifest_before


def test_unregistered_directory_is_not_overwritten(tmp_path: Path, repository: GitHubRepository) -> None:
    repos = tmp_path / "repos"
    source = repos / "example" / "app"
    source.mkdir(parents=True)
    marker = source / "keep.txt"
    marker.write_text("keep")
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="not registered"):
            workspace.clone(repository)
    assert marker.read_text() == "keep"
    assert not (repos / "manifest.json").exists()


@pytest.mark.parametrize("missing", ["source", "git"])
def test_registered_missing_clone_is_not_recloned(
    tmp_path: Path, repository: GitHubRepository, missing: str,
) -> None:
    repos = tmp_path / "repos"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        cloned = workspace.clone(repository)
    target = cloned.source_path if missing == "source" else cloned.source_path / ".git"
    target.rename(tmp_path / "saved")
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="missing or incomplete"):
            workspace.open_registered("example", "app")
    assert not target.exists()


def test_same_name_different_owners_and_case_insensitive_lookup(
    tmp_path: Path, repository: GitHubRepository,
) -> None:
    with RepositoryWorkspace(repos_directory=tmp_path / "repos") as workspace:
        first = workspace.clone(repository)
        second = workspace.clone(repository.model_copy(update={"owner": "another"}))
        assert first.source_path != second.source_path
        assert len(workspace.read_manifest().repositories) == 2
        assert workspace.open_registered("EXAMPLE", "APP").source_path == first.source_path


@pytest.mark.parametrize("content", ["{", '{"schema_version":2}', '\xff'])
def test_invalid_manifest_is_preserved(tmp_path: Path, content: str) -> None:
    repos = tmp_path / "repos"
    repos.mkdir()
    manifest = repos / "manifest.json"
    manifest.write_bytes(content.encode("latin-1"))
    with pytest.raises(RepositoryCloneError, match="manifest could not be read"):
        RepositoryWorkspace(repos_directory=repos).read_manifest()
    assert manifest.read_bytes() == content.encode("latin-1")


@pytest.mark.parametrize("field,value", [
    ("owner", ".."), ("name", "../outside"), ("name", "/outside"),
])
def test_invalid_identity_is_rejected_before_git(
    tmp_path: Path, repository: GitHubRepository, field: str, value: str,
) -> None:
    def unexpected_git(*args, **kwargs):
        pytest.fail("Git must not run for invalid identities")

    with RepositoryWorkspace(repos_directory=tmp_path / "repos", runner=unexpected_git) as workspace:
        with pytest.raises(RepositoryCloneError, match="identity is invalid"):
            workspace.clone(repository.model_copy(update={field: value}))


def test_symlink_path_is_rejected(tmp_path: Path, repository: GitHubRepository) -> None:
    repos = tmp_path / "repos"
    repos.mkdir()
    (repos / "example").symlink_to(tmp_path, target_is_directory=True)
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="symbolic link"):
            workspace.clone(repository)


def test_failed_clone_leaves_no_final_directory_or_registration(
    tmp_path: Path, repository: GitHubRepository,
) -> None:
    repos = tmp_path / "repos"
    broken = repository.model_copy(update={"clone_url": (tmp_path / "missing").as_uri()})
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="Git could not clone"):
            workspace.clone(broken)
        assert not (repos / "example" / "app").exists()
        assert list((repos / "example").iterdir()) == []
        assert workspace.read_manifest().repositories == []
        assert workspace.clone(repository).source_path.exists()


def test_failed_manifest_replace_preserves_previous_manifest(
    tmp_path: Path, repository: GitHubRepository, monkeypatch,
) -> None:
    repos = tmp_path / "repos"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        cloned = workspace.clone(repository)
    previous = (repos / "manifest.json").read_bytes()
    git(cloned.source_path, "commit", "--allow-empty", "-m", "New revision")

    def fail_replace(*args):
        raise OSError("disk full")

    monkeypatch.setattr("repo_vuln_miner.github.workspace.os.replace", fail_replace)
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        with pytest.raises(RepositoryCloneError, match="could not be written"):
            workspace.open_registered("example", "app")
    assert (repos / "manifest.json").read_bytes() == previous
    assert not list(repos.glob(".manifest-*.tmp"))


def test_manifest_does_not_store_urls_or_credentials(
    tmp_path: Path, repository: GitHubRepository,
) -> None:
    metadata = repository.model_copy(update={"url": "https://token:secret@github.com/example/app"})
    repos = tmp_path / "repos"
    with RepositoryWorkspace(repos_directory=repos) as workspace:
        workspace.clone(metadata)
    payload = (repos / "manifest.json").read_text()
    assert "secret" not in payload
    assert "url" not in payload
    entry = json.loads(payload)["repositories"][0]
    assert entry["owner"] == "example"
    assert entry["name"] == "app"


def test_unknown_repository_cannot_trigger_clone(tmp_path: Path) -> None:
    def unexpected_git(*args, **kwargs):
        pytest.fail("Git must not run for an unknown repository")

    with RepositoryWorkspace(repos_directory=tmp_path / "repos", runner=unexpected_git) as workspace:
        with pytest.raises(RepositoryCloneError, match="not registered"):
            workspace.open_registered("example", "unknown")
