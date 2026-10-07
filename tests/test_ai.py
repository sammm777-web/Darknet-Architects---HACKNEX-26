"""
tests/test_ai.py

Test suite for the AI layer in backend/ai_explainer.py:
- Hallucinated log_id triggers exactly one retry, then falls back to template
- Exceptions (timeout, network, missing key) fall back cleanly to template
- The AI's own risk_score and risk_rationale are overwritten by deterministic values
- Invalid reports are never written to cache
- Cache hits return the cached report with source='cache' without API calls
"""

import copy
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.ai_explainer import (
    ai_report,
    compute_risk,
    generate_threat_intelligence,
    template_report,
)


def load_fixtures():
    with open(root_dir / "data" / "mock_chains.json", "r", encoding="utf-8") as f:
        chains = json.load(f)
    with open(root_dir / "data" / "mock_logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)
    with open(root_dir / "data" / "mock_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)
    return chains, logs, report


def make_mock_completion(content_dict: dict) -> MagicMock:
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(content_dict)
    mock_resp = MagicMock()
    mock_resp.choices = [mock_choice]
    return mock_resp


def test_hallucinated_log_id_triggers_retry_then_template():
    """Verify hallucinated log_id triggers one retry, then falls back to template."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    # Fabricate an invalid AI response citing a fake log_id
    invalid_report = copy.deepcopy(report)
    invalid_report["stages"][0]["log_ids"] = ["L-FAKE-99999"]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_mock_completion(invalid_report)

    with tempfile.TemporaryDirectory() as tmp_dir:
        with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        # Assert exactly 2 calls: initial attempt + exactly 1 retry
        assert mock_client.chat.completions.create.call_count == 2, (
            f"Expected exactly 2 OpenAI calls (initial + retry), got {mock_client.chat.completions.create.call_count}"
        )

        final_report = out["report"]
        assert final_report["source"] == "template", f"Expected source 'template', got {final_report.get('source')}"
        assert final_report["citations_verified"] is True
        assert "graph" in out and len(out["graph"]["nodes"]) > 0

    print("  [PASS] test_hallucinated_log_id_triggers_retry_then_template")


def test_thrown_exception_falls_back():
    """Verify exceptions (e.g. timeout, connection error) fall back gracefully to template."""
    chains, logs, _ = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = TimeoutError("Request timed out after 15.0s")

    with tempfile.TemporaryDirectory() as tmp_dir:
        with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        # Only 1 call was attempted before raising exception
        assert mock_client.chat.completions.create.call_count == 1
        final_report = out["report"]
        assert final_report["source"] == "template"
        assert final_report["citations_verified"] is True
        assert "graph" in out

    print("  [PASS] test_thrown_exception_falls_back")


def test_ai_risk_score_is_overwritten():
    """Verify the AI's own hallucinated risk_score and rationale are strictly overwritten."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")

    # The AI attempts to return score 15 and wrong rationale
    ai_candidate = copy.deepcopy(report)
    ai_candidate["risk_score"] = 15
    ai_candidate["risk_rationale"] = "Model invented score"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_mock_completion(ai_candidate)

    with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
        det_score, det_rationale = compute_risk(c1_chain, logs)
        res = ai_report(c1_chain, logs, det_score, det_rationale)

    assert res["risk_score"] == det_score == 100, f"Expected overwritten score {det_score}, got {res['risk_score']}"
    assert res["risk_rationale"] == det_rationale, "Expected overwritten rationale"

    print("  [PASS] test_ai_risk_score_is_overwritten")


def test_invalid_reports_never_cached():
    """Verify that if a report fails validation, it is NEVER written to the cache directory."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_file = Path(tmp_dir) / "C-1.json"

        # Mock validate_citations to return False to simulate validation failure
        with patch("backend.ai_explainer.validate_citations", return_value=False):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        assert out["report"]["citations_verified"] is False
        assert not cache_file.exists(), "Invalid report must NEVER be written to cache!"

    print("  [PASS] test_invalid_reports_never_cached")


def test_cache_hit_returns_cached():
    """Verify cache hit returns cached report with source='cache' without invoking OpenAI API."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    cached_content = copy.deepcopy(report)
    cached_content["summary"] = "Fast cached pre-generated report"

    mock_client = MagicMock()

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_file = Path(tmp_dir) / "C-1.json"
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cached_content, f)

        with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        # OpenAI client was never called
        assert mock_client.chat.completions.create.call_count == 0
        rep = out["report"]
        assert rep["source"] == "cache"
        assert rep["summary"] == "Fast cached pre-generated report"
        assert rep["citations_verified"] is True

    print("  [PASS] test_cache_hit_returns_cached")


def test_invalid_cache_file_triggers_regeneration():
    """Verify an invalid cache file is ignored and triggers regeneration (never returning invalid report)."""
    chains, logs, report = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    # Corrupt the cached report with a fake citation
    corrupted_cache = copy.deepcopy(report)
    corrupted_cache["stages"][0]["log_ids"] = ["L-CORRUPT-FAKE"]
    corrupted_cache["summary"] = "Bad corrupted cached report"

    mock_client = MagicMock()
    # Mock AI to return a valid report upon regeneration
    valid_ai_response = copy.deepcopy(report)
    valid_ai_response["summary"] = "Regenerated AI report"
    mock_client.chat.completions.create.return_value = make_mock_completion(valid_ai_response)

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_file = Path(tmp_dir) / "C-1.json"
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(corrupted_cache, f)

        with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        # AI generation was triggered because cache validation failed
        assert mock_client.chat.completions.create.call_count == 1
        rep = out["report"]
        assert rep["source"] == "ai"
        assert rep["summary"] == "Regenerated AI report"
        assert rep["citations_verified"] is True
        assert "L-CORRUPT-FAKE" not in rep["stages"][0]["log_ids"]

    print("  [PASS] test_invalid_cache_file_triggers_regeneration")


def test_template_report_not_written_to_cache():
    """Verify that a fallback template report is NEVER written to the cache directory."""
    chains, logs, _ = load_fixtures()
    c1_chain = next(c for c in chains if c["chain_id"] == "C-1")
    incident = {"chain": c1_chain, "logs": logs}

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = ConnectionError("Simulated network down")

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_file = Path(tmp_dir) / "C-1.json"
        with patch("backend.ai_explainer.get_openai_client", return_value=mock_client):
            out = generate_threat_intelligence(incident, cache_dir=tmp_dir)

        assert out["report"]["source"] == "template"
        assert out["report"]["citations_verified"] is True
        assert not cache_file.exists(), "Template reports must NOT be written to cache!"

    print("  [PASS] test_template_report_not_written_to_cache")


def main():
    print("[*] Running AI layer test suite for backend/ai_explainer.py...")
    test_hallucinated_log_id_triggers_retry_then_template()
    test_thrown_exception_falls_back()
    test_ai_risk_score_is_overwritten()
    test_invalid_reports_never_cached()
    test_cache_hit_returns_cached()
    test_invalid_cache_file_triggers_regeneration()
    test_template_report_not_written_to_cache()
    print("\n[SUCCESS] All AI tests passed successfully!")


if __name__ == "__main__":
    main()
