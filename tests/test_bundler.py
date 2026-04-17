from pathlib import Path

from security_agent.bundler import parse_gemfile_lock


def test_parse_gemfile_lock_extracts_dependencies(tmp_path: Path) -> None:
    lockfile = tmp_path / "Gemfile.lock"
    lockfile.write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.7)
      rack (~> 2.2, >= 2.2.4)
    nokogiri (1.16.0)
    rack (2.2.7)
    rails (7.0.7)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri
  rails

BUNDLED WITH
   2.5.6
"""
    )

    graph = parse_gemfile_lock(lockfile)
    dependencies = {dependency.name: dependency for dependency in graph.dependencies}

    assert dependencies["rails"].direct is True
    assert dependencies["nokogiri"].direct is True
    assert dependencies["rack"].direct is False
    assert dependencies["rack"].version == "2.2.7"

