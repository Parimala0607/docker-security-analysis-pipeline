# tests/test_epss_scorer.py
from unittest.mock import patch, MagicMock

from analysis.epss_scorer import _fetch_epss_batch, _load_kev


def _resp(rows):
    m = MagicMock()
    m.json.return_value = {"data": rows}
    m.raise_for_status.return_value = None
    return m


def test_batch_fetch_uses_chunked_requests():
    ids = [f"CVE-2024-{i:04d}" for i in range(250)]
    with patch("analysis.epss_scorer.requests.get") as get, \
         patch("analysis.epss_scorer.time.sleep"):
        get.side_effect = lambda url, params, timeout: _resp(
            [{"cve": c, "epss": "0.5"} for c in params["cve"].split(",")]
        )
        scores = _fetch_epss_batch(ids, chunk_size=100)

    assert get.call_count == 3            # 250 ids / 100 per chunk
    assert len(scores) == 250
    assert scores["CVE-2024-0001"] == 0.5


def test_failed_chunk_falls_back_to_single_fetch():
    ids = ["CVE-2024-0001", "CVE-2024-0002"]
    calls = {"n": 0}

    def side_effect(url, params, timeout):
        calls["n"] += 1
        if "," in params["cve"]:          # batch request → always fail
            raise ConnectionError("batch down")
        return _resp([{"cve": params["cve"], "epss": "0.9"}])

    with patch("analysis.epss_scorer.requests.get", side_effect=side_effect), \
         patch("analysis.epss_scorer.time.sleep"):
        scores = _fetch_epss_batch(ids, chunk_size=100)

    assert scores == {"CVE-2024-0001": 0.9, "CVE-2024-0002": 0.9}


def test_load_kev_falls_back_to_empty_set_when_feed_unavailable(monkeypatch):
    import analysis.epss_scorer as scorer

    monkeypatch.setattr(scorer, "_KEV_CACHE", None)

    with patch("analysis.epss_scorer.requests.get", side_effect=ConnectionError("down")):
        assert _load_kev() == set()
