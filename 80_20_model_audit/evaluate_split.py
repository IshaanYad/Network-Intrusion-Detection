import re
import warnings

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")


def extract_features(df):
    df["url"] = df["url"].fillna("")
    df["url_length"] = df["url"].apply(len)
    df["url_special_chars"] = df["url"].apply(
        lambda x: len(re.findall(r"[;'\"<>%&?]", x))
    )
    df["user_agent"] = df["user_agent"].fillna("unknown")
    bots = ["curl", "python-urllib", "sqlmap", "googlebot", "nmap"]
    df["is_bot"] = (
        df["user_agent"]
        .str.lower()
        .apply(lambda x: 1 if any(bot in x for bot in bots) else 0)
    )
    df["is_privileged_port"] = df["dst_port"].apply(lambda x: 1 if x < 1024 else 0)
    df["is_internal_traffic"] = df["is_internal_traffic"].fillna(False).astype(int)

    # Consistent alphabetical encoding: ICMP=0, TCP=1, UDP=2
    protocols = ["ICMP", "TCP", "UDP"]
    df["protocol"] = df["protocol"].astype(str)
    df["protocol_enc"] = df["protocol"].apply(
        lambda x: protocols.index(x) if x in protocols else -1
    )
    return df


print("--- Step 1: Loading & Preprocessing ---")
df = pd.read_csv("cybersecurity.csv")
df = extract_features(df)

cols_to_drop = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "user_agent",
    "url",
    "protocol",
    "attack_type",
    "label",
]
X = df.drop(columns=cols_to_drop)
y = df["label"]

# Step 2: 90/10 Split
print("--- Step 2: Splitting Data (80% Train, 20% Test) ---")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Save test info for display
test_indices = X_test.index
test_attack_types = df.loc[test_indices, "attack_type"].values

# Step 3: Scale and SMOTE
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Applying SMOTE to balance training data...")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

# Step 4: Training (Standard Random Forest)
print("--- Step 3: Training Random Forest (Standard) ---")
model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
model.fit(X_train_res, y_train_res)

# Step 5: Audit
print("\n--- Step 4: Line-by-Line Audit (1000 Entries) ---")
y_pred = model.predict(X_test_scaled)

matches = 0
for i in range(len(y_test)):
    actual = "ATTACK" if y_test.iloc[i] == 1 else "BENIGN"
    pred = "ATTACK" if y_pred[i] == 1 else "BENIGN"
    result = "[CORRECT]" if actual == pred else "[MISMATCH]"
    if actual == pred:
        matches += 1

    if i < 30 or i > 970:
        print(
            f"Entry {i + 1:04d}: Pred: {pred:<7} | Actual: {actual:<7} ({test_attack_types[i]:<15}) {result}"
        )
    elif i == 30:
        print("... (audit in progress) ...")

# Final Metrics
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
print("\n--- FINAL AUDIT SUMMARY (REVERTED) ---")
print(f"Total Correct: {matches} / {len(y_test)} ({matches / len(y_test) * 100:.2f}%)")
print("-" * 30)
print(f"True Negatives (Correctly ignored): {tn}")
print(f"True Positives (Correctly caught): {tp}")
print(f"False Positives (Nuisance alarms): {fp}")
print(f"False Negatives (Missed attacks):  {fn}")
print("-" * 30)
print(classification_report(y_test, y_pred))
