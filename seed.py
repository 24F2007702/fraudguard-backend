import sqlite3, random, sys, time

con = sqlite3.connect("fraudguard.db")
con.execute("CREATE TABLE IF NOT EXISTS reports(key TEXT, kind TEXT, ts REAL, reporter TEXT)")

if len(sys.argv) > 1 and sys.argv[1] == "clear":
    con.execute("DELETE FROM reports WHERE reporter LIKE 'seed-%'")
    con.commit()
    print("Seed data cleared.")
    sys.exit()

ENTITIES = {  # entity: number of reports
    "upi:bijli.office@oksbi": 14,
    "phone:9811122233": 11,
    "domain:sbi-kyc-update.top": 9,
    "upi:support123@okaxis": 6,
    "phone:8800112233": 4,
    "domain:bses-pay.xyz": 3,
    "upi:kbc.winner@ybl": 2,
}
random.seed(7)
now, n = time.time(), 0
for key, count in ENTITIES.items():
    for _ in range(count):
        ts = now - random.uniform(0, 6 * 3600)  # spread over last 6 hours
        con.execute("INSERT INTO reports VALUES(?,?,?,?)", (key, "scam", ts, f"seed-{random.randint(1, 40)}"))
        n += 1
con.commit()
print(f"Seeded {n} reports across {len(ENTITIES)} entities.")
