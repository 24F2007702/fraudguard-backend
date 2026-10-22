s = open("main.py", encoding="utf-8").read()
if "MODEL = joblib" in s:
    print("Already patched."); raise SystemExit

db_line = 'db.execute("CREATE TABLE IF NOT EXISTS reports(key TEXT, kind TEXT, ts REAL, reporter TEXT)")\n'
assert db_line in s, "db line not found"
s = s.replace(db_line, db_line + '''
import os, joblib
MODEL = joblib.load("model.pkl") if os.path.exists("model.pkl") else None
print("ML model loaded" if MODEL else "WARNING: model.pkl not found, using rules only")
''', 1)

a = s.index('@app.post("/analyze")')
b = s.index('@app.post("/report")')
new = r'''@app.post("/analyze")
def analyze(body: AnalyzeIn):
    text = body.text
    t = re.sub(r"(do not|don't|never)\s+share[^.\n]*[.\n]?", " ", text, flags=re.I)
    rule, hits, reasons = 0, 0, []
    for w, rx, why in RULES:
        if rx.search(t): rule += w; hits += 1; reasons.append(why)
    if hits >= 3: rule += 15
    urls, keys = entity_keys(text)
    for u in urls:
        for w, why in url_flags(u): rule += w; reasons.append(why)
    rule = min(100, rule)

    max_n = 0
    for k in keys:
        n = reputation(k)
        if n:
            max_n = max(max_n, n)
            reasons.insert(0, f"{k.replace(':', ' ')} reported {n}x in the last 7 days")
    rep = min(100, 30 * max_n)

    ml = round(MODEL.predict_proba([text])[0][1] * 100) if MODEL else rule
    if MODEL and ml >= 70: reasons.append(f"AI model: {ml}% similar to known scam messages")

    blend = 0.45 * ml + 0.35 * rule + 0.20 * rep
    risk = round(max(blend, 0.85 * rule, 0.9 * rep))
    risk = max(5, min(99, risk))
    verdict = "High Risk" if risk >= 60 else "Caution" if risk >= 30 else "Safe"
    action = {"High Risk": "Do NOT pay, click or share OTP. Report at cybercrime.gov.in or call 1930.",
              "Caution": "Verify via the official app/website or the number printed on your bill/card first.",
              "Safe": "No strong scam signals found. Still, never share OTP/PIN with anyone."}[verdict]
    return {"risk": risk, "verdict": verdict, "reasons": list(dict.fromkeys(reasons)), "action": action,
            "keys": keys, "ml": ml, "rule": rule, "rep": rep}


'''
s = s[:a] + new + s[b:]
open("main.py", "w", encoding="utf-8").write(s)
print("Patched OK. Now restart uvicorn.")