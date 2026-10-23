"""FraudGuard backend: community reputation + (optional) ML. Run: uvicorn main:app --reload --port 8000"""
import re, sqlite3, time
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="FraudGuard AI")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
db = sqlite3.connect("fraudguard.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS reports(key TEXT, kind TEXT, ts REAL, reporter TEXT)")

import os, joblib
MODEL = joblib.load("model.pkl") if os.path.exists("model.pkl") else None
print("ML model loaded" if MODEL else "WARNING: model.pkl not found, using rules only")

HANDLES = "ybl|oksbi|okhdfcbank|okicici|okaxis|paytm|upi|ibl|axl|apl|sbi|icici|hdfcbank|axisbank|pnb|fbl|airtel|jio|ikwik|freecharge"
UPI_RE = re.compile(r"(?<![\w.@-])[\w.\-]{2,}@(?:%s)\b" % HANDLES, re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')]+", re.I)
BAD_TLD = re.compile(r"\.(xyz|top|click|live|icu|site|online|buzz|shop|vip|cfd|sbs|monster)$")
BRANDS = {"sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"],
          "paytm": ["paytm.com"], "phonepe": ["phonepe.com"], "npci": ["npci.org.in"], "irctc": ["irctc.co.in"]}
RULES = [
    (15, r"\b(immediately|urgent(ly)?|tonight|right now|within \d+ ?(hours?|mins?|minutes?)|last warning|abhi|turant)\b", "Urgency/threat language to rush you"),
    (25, r"(electricity|bijli|power supply).{0,50}(cut|disconnect|off|band)", 'Matches the fake "electricity will be cut" scam'),
    (25, r"\bkyc\b.{0,50}(expire|update|block|suspend|pending|verify)", "Fake KYC update/expiry pattern"),
    (35, r"(digital arrest|cbi|narcotics|customs|ed officer|police).{0,80}(arrest|seiz|fir|warrant|parcel)", '"Digital arrest" / fake authority pattern'),
    (30, r"\b(share|send|tell|give)\b.{0,20}\b(otp|pin|cvv|password)\b", "Asks you to share OTP/PIN/password"),
    (25, r"(lottery|you(?:'ve| have)? won|lucky draw|prize money|kbc)", "Lottery/prize bait"),
    (20, r"(work from home|part[- ]?time job|task job).{0,80}(earn|daily|salary|₹|rs\.?)", "Too-good-to-be-true job offer"),
    (20, r"(guaranteed|assured).{0,30}(returns?|profit)|double your money|trading group", "Guaranteed-returns investment bait"),
    (30, r"\b(anydesk|teamviewer|quicksupport|rustdesk)\b", "Asks you to install a remote-access app"),
    (15, r"(pay|send|transfer).{0,40}(₹|rs\.?|inr)\s?\d|\bupi\b|\bvpa\b", "Payment demand via message/UPI"),
    (10, r"\b(refund|cashback|reward points?)\b.{0,40}(claim|click|link|expire)", "Refund/reward claim bait"),
]
RULES = [(w, re.compile(p, re.I | re.S), why) for w, p, why in RULES]


def host(u):
    return (urlparse(u if u.lower().startswith("http") else "http://" + u).hostname or "").lower()


def entity_keys(text):
    upi = {m.group(0).lower() for m in UPI_RE.finditer(text)}
    phones = {re.sub(r"\D", "", m.group(0))[-10:] for m in PHONE_RE.finditer(text)}
    urls = {m.group(0) for m in URL_RE.finditer(text)}
    doms = {host(u) for u in urls if host(u)}
    return urls, [f"upi:{x}" for x in upi] + [f"phone:{x}" for x in phones] + [f"domain:{x}" for x in doms]


def url_flags(u):
    h, f = host(u), []
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h): f.append((30, "Link uses a raw IP address"))
    if h in {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"}: f.append((20, "Shortened link hides the real destination"))
    if BAD_TLD.search(h): f.append((25, "Link uses a TLD popular with scam sites"))
    toks = re.split(r"[.\-]", h)
    for b, off in BRANDS.items():
        if b in toks and not any(h == d or h.endswith("." + d) for d in off):
            f.append((45, f"Domain imitates {b.upper()} but is not official"))
    return [(w, f"{why} ({h})") for w, why in f]


def reputation(key):
    since = time.time() - 7 * 86400
    q = lambda k: db.execute("SELECT COUNT(*) FROM reports WHERE key=? AND kind=? AND ts>?", (key, k, since)).fetchone()[0]
    return max(0, q("scam") - q("safe"))


class AnalyzeIn(BaseModel):
    text: str


class ReportIn(BaseModel):
    keys: list[str]
    kind: str = "scam"
    reporter: str = "anon"


@app.post("/analyze")
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
    # strong rules / heavy community reports must not be diluted by the blend
    risk = round(max(blend, 0.85 * rule, 0.9 * rep))
    risk = max(5, min(99, risk))
    verdict = "High Risk" if risk >= 60 else "Caution" if risk >= 30 else "Safe"
    action = {"High Risk": "Do NOT pay, click or share OTP. Report at cybercrime.gov.in or call 1930.",
              "Caution": "Verify via the official app/website or the number printed on your bill/card first.",
              "Safe": "No strong scam signals found. Still, never share OTP/PIN with anyone."}[verdict]
    return {"risk": risk, "verdict": verdict, "reasons": list(dict.fromkeys(reasons)), "action": action,
            "keys": keys, "ml": ml, "rule": rule, "rep": rep}


@app.post("/report")
def report(body: ReportIn):
    added, now = 0, time.time()
    for k in body.keys:
        dup = db.execute("SELECT 1 FROM reports WHERE key=? AND reporter=? AND ts>?", (k, body.reporter, now - 86400)).fetchone()
        if not dup:
            db.execute("INSERT INTO reports VALUES(?,?,?,?)", (k, body.kind, now, body.reporter)); added += 1
    db.commit()
    return {"added": added}


@app.get("/stats")  # feed this to your Streamlit dashboard
def stats():
    rows = db.execute("SELECT key, COUNT(*) c FROM reports WHERE kind='scam' AND ts>? GROUP BY key ORDER BY c DESC LIMIT 20",
                      (time.time() - 7 * 86400,)).fetchall()
    return {"top_reported": [{"key": k, "reports": c} for k, c in rows]}

import sqlite3

@app.get("/reports")
def reports(limit: int = 2000):
    con = sqlite3.connect("fraudguard.db")
    rows = con.execute(
        "SELECT key, kind, ts, reporter FROM reports ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    con.close()
    return [{"key": r[0], "kind": r[1], "ts": r[2], "reporter": r[3]} for r in rows]