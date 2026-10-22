import json, sqlite3, time, urllib.request
import pandas as pd
import streamlit as st

DB, API = "fraudguard.db", "http://localhost:8000"
st.set_page_config(page_title="FraudGuard Command Centre", page_icon="🛡️", layout="wide")
st.title("🛡️ FraudGuard AI – Command Centre")
st.caption("Live community scam intelligence for banks, telecoms and cyber-police")


def load():
    try:
        con = sqlite3.connect(DB)
        df = pd.read_sql_query("SELECT key, kind, ts, reporter FROM reports", con)
        con.close()
    except Exception:
        return pd.DataFrame()
    if df.empty:
        return df
    df["time"] = pd.to_datetime(df["ts"], unit="s", utc=True).dt.tz_convert("Asia/Kolkata").dt.tz_localize(None)
    df["type"] = df["key"].str.split(":").str[0]
    df["entity"] = df["key"].str.split(":", n=1).str[1]
    return df


@st.fragment(run_every=5)  # auto-refresh every 5 sec -> live updates during demo
def live():
    df = load()
    scam = df[df["kind"] == "scam"] if not df.empty else df
    if scam.empty:
        st.info("No reports yet. Report a scam from the extension, or run: python seed.py")
        return
    top = scam["key"].value_counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Scam reports (24h)", int((scam["ts"] > time.time() - 86400).sum()))
    c2.metric("Flagged entities", scam["key"].nunique())
    c3.metric("Active reporters", scam["reporter"].nunique())
    c4.metric("Top entity reports", int(top.iloc[0]))

    left, right = st.columns(2)
    with left:
        st.subheader("🚨 Most reported UPI IDs / numbers / domains")
        st.bar_chart(top.head(8))
    with right:
        st.subheader("📈 Reports per hour")
        st.line_chart(scam.set_index("time").resample("1h").size())

    l2, r2 = st.columns(2)
    with l2:
        st.subheader("Entity types")
        st.bar_chart(scam["type"].value_counts())
    with r2:
        st.subheader("🔴 Live feed")
        feed = scam.sort_values("ts", ascending=False)[["time", "type", "entity"]].head(10)
        st.dataframe(feed, hide_index=True)


live()

st.divider()
st.subheader("🔍 Analyze a message")
msg = st.text_area("Paste a suspicious message", height=100)
if st.button("Analyze") and msg.strip():
    try:
        req = urllib.request.Request(API + "/analyze", data=json.dumps({"text": msg}).encode(),
                                     headers={"Content-Type": "application/json"})
        r = json.load(urllib.request.urlopen(req, timeout=5))
        a, b, c, d = st.columns(4)
        a.metric("Final risk", f"{r['risk']}%")
        b.metric("AI model (45%)", f"{r.get('ml', '-')}%")
        c.metric("Rules (35%)", f"{r.get('rule', '-')}%")
        d.metric("Community (20%)", f"{r.get('rep', '-')}%")
        {"High Risk": st.error, "Caution": st.warning, "Safe": st.success}[r["verdict"]](r["verdict"])
        for x in r["reasons"]:
            st.write("•", x)
        st.info(r["action"])
    except Exception:
        st.error("Backend not reachable on localhost:8000. Start uvicorn first.")
