import pandas as pd
import numpy as np
import re
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE

# 1. Reuse the Feature Engineering Logic
def extract_features(df):
    df['url'] = df['url'].fillna('')
    df['url_length'] = df['url'].apply(len)
    df['url_special_chars'] = df['url'].apply(lambda x: len(re.findall(r"[;'\"<>%&?]", x)))
    df['user_agent'] = df['user_agent'].fillna('unknown')
    bots = ['curl', 'python-urllib', 'sqlmap', 'googlebot', 'nmap']
    df['is_bot'] = df['user_agent'].str.lower().apply(lambda x: 1 if any(bot in x for bot in bots) else 0)
    df['is_privileged_port'] = df['dst_port'].apply(lambda x: 1 if x < 1024 else 0)
    df['is_internal_traffic'] = df['is_internal_traffic'].fillna(False).astype(int)
    # e. Protocol Encoding (consistent across training and test)
    protocols = ['ICMP', 'TCP', 'UDP']
    df['protocol'] = df['protocol'].astype(str)
    df['protocol_enc'] = df['protocol'].apply(lambda x: protocols.index(x) if x in protocols else -1)
    return df

def train_and_predict(test_csv_path):
    # Load Training Data to "Build" the model
    print("--- Training Model on Full Dataset ---")
    df_train = pd.read_csv('data/cybersecurity.csv')
    df_train = extract_features(df_train)
    
    cols_to_drop = ['timestamp', 'src_ip', 'dst_ip', 'user_agent', 'url', 'protocol', 'attack_type', 'label']
    X_train = df_train.drop(columns=cols_to_drop)
    y_train = df_train['label']

    # Scale and Balance
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

    # Train the Winner (Random Forest)
    model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, class_weight={0: 1, 1: 10})
    model.fit(X_train_res, y_train_res)

    # Load and Process YOUR Custom CSV
    print(f"--- Processing: {test_csv_path} ---")
    df_test = pd.read_csv(test_csv_path)
    df_test_processed = extract_features(df_test)
    
    # Drop columns that are NOT in the training features
    # (Handling cases where the user's CSV might or might not have 'label')
    X_test = df_test_processed.drop(columns=[c for c in cols_to_drop if c in df_test_processed.columns])
    
    # Ensure columns match training order
    X_test = X_test[X_train.columns]
    
    X_test_scaled = scaler.transform(X_test)
    predictions = model.predict(X_test_scaled)

    # Output Results
    print("\n--- PREDICTION RESULTS ---")
    for i, pred in enumerate(predictions):
        status = "!!! [ATTACK] !!!" if pred == 1 else "[BENIGN]"
        print(f"Entry {i+1}: {status}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python predict_custom.py <your_csv_file.csv>")
    else:
        train_and_predict(sys.argv[1])
