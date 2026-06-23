import pandas as pd
import numpy as np
import re
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE

def extract_features(df):
    df['url'] = df['url'].fillna('')
    df['url_length'] = df['url'].apply(len)
    df['url_special_chars'] = df['url'].apply(lambda x: len(re.findall(r"[;'\"<>%&?]", x)))
    df['user_agent'] = df['user_agent'].fillna('unknown')
    bots = ['curl', 'python-urllib', 'sqlmap', 'googlebot', 'nmap']
    df['is_bot'] = df['user_agent'].str.lower().apply(lambda x: 1 if any(bot in x for bot in bots) else 0)
    df['is_privileged_port'] = df['dst_port'].apply(lambda x: 1 if x < 1024 else 0)
    df['is_internal_traffic'] = df['is_internal_traffic'].fillna(False).astype(int)
    protocols = ['ICMP', 'TCP', 'UDP']
    df['protocol_enc'] = df['protocol'].astype(str).apply(lambda x: protocols.index(x) if x in protocols else -1)
    return df

df_train = pd.read_csv('data/cybersecurity.csv')
df_train = extract_features(df_train)

cols_to_drop = ['timestamp', 'src_ip', 'dst_ip', 'user_agent', 'url', 'protocol', 'attack_type', 'label']
X = df_train.drop(columns=cols_to_drop)
y = df_train['label']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
smote = SMOTE(random_state=42)
X_res, y_res = smote.fit_resample(X_scaled, y)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_res, y_res)

feat_importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
print(feat_importances)
