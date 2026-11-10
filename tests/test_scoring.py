from mcp_ti.engine.scoring import assess


def src(name, status="ok", **data):
    return {"name": name, "status": status, "data": data}


def test_whitelisted_ip_is_low():
    r = assess([
        src("AbuseIPDB", abuse_score=0, total_reports=187, is_whitelisted=True, max_age_days=90),
        src("VirusTotal", malicious=1, suspicious=0, harmless=53, undetected=38),
    ])
    assert r["risk_level"] == "low"


def test_eicar_is_high():
    r = assess([src("VirusTotal", malicious=66, suspicious=0, harmless=0, undetected=2)])
    assert r["risk_level"] == "high"


def test_suspicious_domain_is_medium():
    r = assess([src("VirusTotal", malicious=2, suspicious=2, harmless=56, undetected=32)])
    assert r["risk_level"] == "medium"


def test_not_found_is_unknown_not_safe():
    r = assess([{"name": "VirusTotal", "status": "not_found", "data": {}}])
    assert r["risk_level"] == "unknown" and r["score"] is None
    assert any("NOT mean" in line for line in r["rationale"])


def test_failed_source_gives_partial_result():
    r = assess([
        {"name": "AbuseIPDB", "status": "error", "data": {}},
        src("VirusTotal", malicious=66, suspicious=0, harmless=0, undetected=2),
    ])
    assert r["risk_level"] == "high"
    assert r["coverage"] == 0.5
    assert any("Incomplete" in line for line in r["rationale"])
