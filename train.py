import random, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report

random.seed(42)
AMT = ["₹499", "₹2,499", "Rs 5000", "₹9,999", "Rs. 12000", "Rs 750"]
UPI = ["rahul.kumar@ybl", "pay9876@paytm", "bijli.office@oksbi", "support123@okaxis", "9876543210@ibl"]
LINK = ["http://bit.ly/3xYz", "http://sbi-kyc-update.top/login", "https://bses-pay.xyz/bill", "http://paytm-reward.click/claim"]
PRE = ["", "", "Dear customer, ", "URGENT: ", "Hello, ", "Sir, ", "Notice: "]

SCAM = [
    "Your electricity will be cut tonight. Pay {amt} to {upi} immediately",
    "Bijli bill pending. Aaj raat connection kat jayega. Turant {amt} bhejo {upi}",
    "Your KYC will expire today. Update now {link}",
    "SBI KYC pending account will be blocked. Click {link} and share OTP",
    "CBI officer here. You are under digital arrest. Parcel with drugs seized. Pay {amt} to {upi} to avoid FIR",
    "Congratulations! You won KBC lottery of Rs 25,00,000. Pay {amt} processing fee to {upi}",
    "Work from home part time job earn Rs 5000 daily. Join now {link}",
    "Guaranteed returns, double your money in 7 days. Join trading group {link}",
    "Install AnyDesk and share the code, we will refund your {amt}",
    "Your account is suspended. Share OTP immediately to reactivate",
    "Aapka parcel customs mein ruka hai. {amt} pay karo {upi} warna case darj hoga",
    "Refund of {amt} pending. Claim now {link} expires in 1 hour",
    "Loan approved instantly no documents. Pay {amt} processing fee to {upi}",
    "Aapka SIM band ho jayega. Abhi KYC update karo {link}",
    "Your PAN card is blocked. Click {link} to verify immediately",
    "Sent money by mistake, please return {amt} to {upi} urgently",
    "Dear user your bank account will be freezed. Call this number and tell your PIN",
    "Police case registered against your Aadhaar. Contact officer now, pay {amt} to {upi}",
]
LEGIT = [
    "Your Amazon order is out for delivery today. Track it in the app",
    "Your OTP is 482913. Do not share it with anyone. - HDFC Bank",
    "Rs 500 debited from a/c XX1234 on 22-Oct. If not you, call the number on your card",
    "Hi, are we still meeting at 5 pm for the project discussion?",
    "Your mobile recharge of {amt} was successful. Thank you for using the app",
    "Reminder: your electricity bill of {amt} is due on 30th. Pay via the official app or website",
    "Bhai kal ka match dekhne chalein? Ghar pe aa jaana",
    "Your Swiggy order has been delivered. Rate your experience",
    "Aapka appointment kal 11 baje confirm hai. Clinic ka address same hai",
    "Your train ticket PNR 1234567890 is confirmed. Happy journey",
    "Happy birthday! Party at my place on Saturday, bring snacks",
    "Mom: dinner at 8, don't be late. Also pick up milk",
    "Your payment of {amt} to Zomato was successful. Ref no 88123",
    "Salary credited: {amt} to your a/c XX5678. Available balance updated in the app",
    "Assignment deadline extended to Friday. Submit on the college portal",
    "Your cab is arriving in 3 minutes. Driver: Ramesh, Swift Dzire",
    "Thanks for banking with us. Never share your OTP or PIN with anyone",
    "Netflix: your plan renews on 3rd Nov. Manage it in account settings",
]

def make(templates, n):
    out = []
    for _ in range(n):
        t = random.choice(templates)
        s = random.choice(PRE) + t.format(amt=random.choice(AMT), upi=random.choice(UPI), link=random.choice(LINK))
        if random.random() < 0.2: s = s.lower()
        out.append(s)
    return out

def pipe():
    return make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=True, sublinear_tf=True),
                         LogisticRegression(max_iter=1000, C=5, class_weight="balanced"))

# Honest eval: test on templates the model has NEVER seen
HOLD = 4
Xtr = make(SCAM[:-HOLD], 300) + make(LEGIT[:-HOLD], 300); ytr = [1] * 300 + [0] * 300
Xte = make(SCAM[-HOLD:], 100) + make(LEGIT[-HOLD:], 100); yte = [1] * 100 + [0] * 100
m = pipe().fit(Xtr, ytr)
print("== Unseen-template test ==")
print(classification_report(yte, m.predict(Xte), target_names=["legit", "scam"]))

# Final model on everything
X = make(SCAM, 300) + make(LEGIT, 300); y = [1] * 300 + [0] * 300
final = pipe().fit(X, y)
joblib.dump(final, "model.pkl")
print("model.pkl saved")
for s in ["Your electricity will be cut tonight. Pay Rs 2499 to a@ybl immediately",
          "Your Amazon order is out for delivery", "Aapka KYC expire ho gaya, abhi link pe click karo",
          "Hi bro dinner at 8?"]:
    print(round(final.predict_proba([s])[0][1] * 100), "%", s)