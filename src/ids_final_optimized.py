import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE
import warnings
import json

warnings.filterwarnings('ignore')

# 1. Data Loading & Feature Engineering
def extract_features(df):
    df['url'] = df['url'].fillna('')
    df['url_length'] = df['url'].apply(len)
    df['url_special_chars'] = df['url'].apply(lambda x: len(re.findall(r"[;'\"<>%&?]", x)))
    df['user_agent'] = df['user_agent'].fillna('unknown')
    bots = ['curl', 'python-urllib', 'sqlmap', 'googlebot', 'nmap']
    df['is_bot'] = df['user_agent'].str.lower().apply(lambda x: 1 if any(bot in x for bot in bots) else 0)
    df['is_privileged_port'] = df['dst_port'].apply(lambda x: 1 if x < 1024 else 0)
    df['is_internal_traffic'] = df['is_internal_traffic'].fillna(False).astype(int)
    le = LabelEncoder()
    df['protocol_enc'] = le.fit_transform(df['protocol'].astype(str))
    return df

print("--- Loading & Preprocessing ---")
df = pd.read_csv('data/cybersecurity.csv')
df = extract_features(df)

cols_to_drop = ['timestamp', 'src_ip', 'dst_ip', 'user_agent', 'url', 'protocol', 'attack_type']
X = df.drop(columns=cols_to_drop + ['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

# 2. Hyperparameter Tuning (Grid Search)
print("--- Hyperparameter Tuning (Random Forest) ---")
rf_param_grid = {
    'n_estimators': [50, 100],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5]
}

rf_grid = GridSearchCV(RandomForestClassifier(random_state=42), rf_param_grid, cv=3, scoring='f1', n_jobs=-1)
rf_grid.fit(X_train_res, y_train_res)
best_rf = rf_grid.best_estimator_
print(f"Best RF Params: {rf_grid.best_params_}")

# 3. Cross-Validation
print("--- Performing 5-Fold Cross-Validation ---")
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(best_rf, X_train_res, y_train_res, cv=skf, scoring='f1')
print(f"CV F1-Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# 4. Final Evaluation
print("--- Final Evaluation ---")
y_pred = best_rf.predict(X_test_scaled)

final_metrics = {
    "Accuracy": accuracy_score(y_test, y_pred),
    "Precision": precision_score(y_test, y_pred),
    "Recall": recall_score(y_test, y_pred),
    "F1-Score": f1_score(y_test, y_pred),
    "CV_Mean_F1": cv_scores.mean()
}

print(classification_report(y_test, y_pred))

# Save Metrics
with open('outputs/final_metrics.json', 'w') as f:
    json.dump(final_metrics, f, indent=4)

# Save Confusion Matrix Plot
plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Final Model Confusion Matrix')
plt.savefig('outputs/final_confusion_matrix.png')

print("Final optimization complete. Results saved in 'outputs/'.")

# --- ADDED: TEST AGAINST BLIND TEST CSV ---
import os
if os.path.exists('blind_test.csv'):
    print("\n--- Testing Against blind_test.csv ---")
    df_blind = pd.read_csv('blind_test.csv')
    df_blind = extract_features(df_blind)
    X_blind = df_blind.drop(columns=[c for c in (cols_to_drop + ['label']) if c in df_blind.columns])
    X_blind = X_blind[X.columns]
    X_blind_scaled = scaler.transform(X_blind)
    blind_preds = best_rf.predict(X_blind_scaled)
    
    for i, pred in enumerate(blind_preds):
        status = "!!! [ATTACK] !!!" if pred == 1 else "[BENIGN]"
        print(f"Entry {i+1}: {status}")
