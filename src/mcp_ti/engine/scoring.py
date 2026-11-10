# Thresholds are design choices; justify them in the report (calibration set).
HIGH, MEDIUM = 70, 30


def assess(sources: list[dict]) -> dict:
    ok = [s for s in sources if s["status"] == "ok"]
    if not ok:
        return {"risk_level": "unknown", "score": None, "coverage": 0.0,
                "rationale": ["No source returned usable data. This does NOT mean the IOC is safe."]}

    signals, rationale = [], []
    for s in ok:
        d = s["data"]
        if s["name"] == "AbuseIPDB":
            if d.get("is_whitelisted"):
                signals.append(0.0)
                rationale.append(
                    f"AbuseIPDB: address is whitelisted; {d['total_reports']} reports ignored.")
            else:
                signals.append(d["abuse_score"] / 100)
                rationale.append(
                    f"AbuseIPDB: confidence {d['abuse_score']}/100 "
                    f"({d['total_reports']} reports, last {d['max_age_days']} days).")
        elif s["name"] == "VirusTotal":
            m, sus = d["malicious"], d["suspicious"]
            total = m + sus + d["harmless"] + d["undetected"]
            signals.append(min(1.0, (m + 0.5 * sus) / 10))
            sus_txt = f" and {sus} as suspicious" if sus else ""
            note = " Few detections: weak evidence on its own." if 0 < m < 3 else ""
            rationale.append(
                f"VirusTotal: {m} of {total} engines flag it as malicious{sus_txt}.{note}")
        elif s["name"] == "MISP":
            if d["matches"] == 0:
                rationale.append(
                    "MISP: no match in the local instance. This does not mean the IOC is safe.")
            else:
                signals.append(0.8 if d["to_ids"] else 0.5)
                flagged = ", flagged for detection" if d["to_ids"] else ""
                rationale.append(
                    f"MISP: {d['matches']} attribute(s) in {d['events']} event(s){flagged}.")

    if not signals:
        return {"risk_level": "unknown", "score": None,
                "coverage": round(len(ok) / len(sources), 2),
                "rationale": rationale + ["No source provided a risk signal. This does NOT mean the IOC is safe."]}

    score = max(signals)
    if sum(1 for x in signals if x >= 0.3) >= 2:
        score = min(1.0, score + 0.1)
        rationale.append("Corroborated by several sources.")
    if max(signals) >= 0.5 and min(signals) == 0:
        rationale.append("Sources disagree; both views are kept in the evidence.")
    if len(ok) == 1:
        rationale.append("Only one source answered; the verdict is limited.")

    pct = round(score * 100)
    level = "high" if pct >= HIGH else "medium" if pct >= MEDIUM else "low"
    failed = [s["name"] for s in sources if s["status"] != "ok"]
    if failed:
        rationale.append(f"Incomplete: no usable answer from {', '.join(failed)}.")
    return {"risk_level": level, "score": pct,
            "coverage": round(len(ok) / len(sources), 2), "rationale": rationale}
