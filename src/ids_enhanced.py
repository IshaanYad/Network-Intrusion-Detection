import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE
import warnings

warnings.filterwarnings('ignore')

# 1. Data Loading
print("--- Loading Data ---")
df = pd.read_csv('data/cybersecurity.csv')

# 2. Enhanced Feature Engineering
print("--- Performing Enhanced Feature Engineering ---")

def extract_features(df):
    # a. URL Features
    # Fill NaNs first
    df['url'] = df['url'].fillna('')
    df['url_length'] = df['url'].apply(len)
    # Count special characters often used in injections (SQLi, XSS)
    df['url_special_chars'] = df['url'].apply(lambda x: len(re.findall(r"[;'\"<>%&?]", x)))
    
    # b. User-Agent Features
    df['user_agent'] = df['user_agent'].fillna('unknown')
    # Identify common bots/automated tools found in the dataset
    bots = ['curl', 'python-urllib', 'sqlmap', 'googlebot', 'nmap']
    df['is_bot'] = df['user_agent'].str.lower().apply(lambda x: 1 if any(bot in x for bot in bots) else 0)
    
    # c. Network Features
    # Identify if it's a common privileged port (0-1023)
    df['is_privileged_port'] = df['dst_port'].apply(lambda x: 1 if x < 1024 else 0)
    
    # d. Metadata
    df['is_internal_traffic'] = df['is_internal_traffic'].fillna(False).astype(int)
    
    # e. Protocol Encoding
    le = LabelEncoder()
    df['protocol_enc'] = le.fit_transform(df['protocol'].astype(str))
    
    return df

df_enhanced = extract_features(df)

# Drop raw strings and irrelevant columns
cols_to_drop = ['timestamp', 'src_ip', 'dst_ip', 'user_agent', 'url', 'protocol', 'attack_type']
X = df_enhanced.drop(columns=cols_to_drop + ['label'])
y = df_enhanced['label']

print(f"Features used for training: {list(X.columns)}")

# 3. Split & Scale
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 4. Handle Imbalance
print("Applying SMOTE...")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

# 5. Train Top Models (Random Forest & XGBoost)
print("--- Training Enhanced Models ---")

models = {
    "Enhanced Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "Enhanced XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
}

enhanced_results = []

for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train_res, y_train_res)
    y_pred = model.predict(X_test_scaled)
    
    metrics = {
        "Model": name,
        "Accuracy": accuracy_score(y_test, y_pred),
        "Precision": precision_score(y_test, y_pred),
        "Recall": recall_score(y_test, y_pred),
        "F1-Score": f1_score(y_test, y_pred)
    }
    enhanced_results.append(metrics)
    
    print(f"{name} Results:")
    print(confusion_matrix(y_test, y_pred))
    print(f"Recall: {metrics['Recall']:.4f}")
    print("-" * 30)

# 6. Save & Compare
new_results_df = pd.DataFrame(enhanced_results)
new_results_df.to_csv('outputs/enhanced_results.csv', index=False)

# Visualize Feature Importance for Random Forest
rf_model = models["Enhanced Random Forest"]
importances = rf_model.feature_importances_
feat_importances = pd.Series(importances, index=X.columns).sort_values(ascending=True)

plt.figure(figsize=(10, 6))
feat_importances.plot(kind='barh')
plt.title('Feature Importance (Enhanced Random Forest)')
plt.tight_layout()
plt.savefig('outputs/feature_importance.png')

print("Enhanced results and feature importance plot saved in 'outputs/'")
