from security_agent.models import EvidenceItem, ScanResult, VulnerabilityFinding
from security_agent.reporting import render_terminal


def test_render_terminal_includes_investigation_details() -> None:
    finding = VulnerabilityFinding(
        gem_name="rails",
        installed_version="7.0.7",
        direct_dependency=True,
        advisory_id="SA-TEST",
        severity="high",
        summary="fixture",
        fixed_versions=["7.0.8"],
        investigated=True,
        investigator_used="openai",
        reachability_status="reachable",
        confidence=0.86,
        reasoning_summary="Observed rails referenced from application code.",
        evidence=[
            EvidenceItem(
                kind="text_match",
                summary="Matched search term in app/services/example.rb:4",
                path="app/services/example.rb",
                line=4,
            )
        ],
        priority="high",
    )
    result = ScanResult(
        repo_path="/tmp/sample",
        repo_kind="rails",
        dependency_count=3,
        findings=[finding],
    )

    rendered = render_terminal(result)

    assert "security-agent" in rendered
    assert "Investigated: 1" in rendered
    assert "Investigator: openai" in rendered
    assert "Reachability: reachable" in rendered
    assert "Confidence: 0.86" in rendered
    assert "Investigation: Observed rails referenced from application code." in rendered
    assert "Evidence: Matched search term in app/services/example.rb:4" in rendered


def test_render_terminal_color_mode_adds_ansi_sequences() -> None:
    finding = VulnerabilityFinding(
        gem_name="rails",
        installed_version="7.0.7",
        direct_dependency=True,
        advisory_id="SA-TEST",
        severity="high",
        summary="fixture",
        fixed_versions=["7.0.8"],
        investigated=True,
        investigator_used="openai",
        reachability_status="reachable",
        confidence=0.86,
        priority="high",
    )
    result = ScanResult(
        repo_path="/tmp/sample",
        repo_kind="rails",
        dependency_count=3,
        findings=[finding],
    )

    rendered = render_terminal(result, color_enabled=True)

    assert "\u001b[" in rendered
