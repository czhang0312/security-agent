from __future__ import annotations

from pathlib import Path

from security_agent.models import RepoInfo


class UnsupportedRepoError(RuntimeError):
    pass


def detect_repo(repo_path: str) -> RepoInfo:
    root = Path(repo_path).expanduser().resolve()

    has_gemfile = (root / "Gemfile").exists()
    has_lockfile = (root / "Gemfile.lock").exists()
    has_app_dir = (root / "app").is_dir()
    has_config_dir = (root / "config").is_dir()
    has_routes = (root / "config" / "routes.rb").exists()

    if has_gemfile and has_lockfile and has_app_dir and has_config_dir and has_routes:
        return RepoInfo(root=str(root), kind="rails")

    return RepoInfo(root=str(root), kind="unknown")

