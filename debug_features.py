import pandas as pd
import re
from sklearn.preprocessing import LabelEncoder

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

df = pd.read_csv('blind_test.csv')
df = extract_features(df)
print(df[['url_special_chars', 'is_bot', 'is_privileged_port', 'protocol_enc']])
