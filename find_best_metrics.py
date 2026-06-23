import re
import warnings
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, recall_score, precision_score, accuracy_score
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

    protocols = ["ICMP", "TCP", "UDP"]
    df["protocol"] = df["protocol"].astype(str)
    df["protocol_enc"] = df["protocol"].apply(
        lambda x: protocols.index(x) if x in protocols else -1
    )
    return df

def evaluate_combination(X, y, split, thresholds):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=split, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

    model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
    model.fit(X_train_res, y_train_res)

    y_probs = model.predict_proba(X_test_scaled)[:, 1]
    
    results = []
    for threshold in thresholds:
        y_pred = (y_probs >= threshold).astype(int)
        f1 = f1_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        accuracy = accuracy_score(y_test, y_pred)
        results.append({
            'split': split,
            'threshold': threshold,
            'f1': f1,
            'recall': recall,
            'precision': precision,
            'accuracy': accuracy
        })
    return results

def main():
    print("Loading data...")
    df = pd.read_csv("cybersecurity.csv")
    df = extract_features(df)

    cols_to_drop = ["timestamp", "src_ip", "dst_ip", "user_agent", "url", "protocol", "attack_type", "label"]
    X = df.drop(columns=cols_to_drop)
    y = df["label"]

    splits = [0.1, 0.2, 0.3, 0.4]
    thresholds = np.arange(0.1, 1.0, 0.1)
    
    all_results = []

    print(f"Starting grid search over {len(splits)} splits and {len(thresholds)} thresholds...")
    
    for split in splits:
        print(f"Evaluating split: {1-split}/{split}...")
        split_results = evaluate_combination(X, y, split, thresholds)
        all_results.extend(split_results)

    results_df = pd.DataFrame(all_results)
    
    metrics = ['f1', 'recall', 'precision', 'accuracy']
    
    print("\n" + "="*60)
    print("BEST COMBINATIONS PER METRIC")
    print("="*60)
    
    for metric in metrics:
        best_row = results_df.loc[results_df[metric].idxmax()]
        print(f"\n---> HIGHEST {metric.upper()}:")
        print(f"Value:      {best_row[metric]:.4f}")
        print(f"Split:      {1-best_row['split']}/{best_row['split']}")
        print(f"Threshold:  {best_row['threshold']:.1f}")
        print(f"F1-Score:   {best_row['f1']:.4f}")
        print(f"Recall:     {best_row['recall']:.4f}")
        print(f"Precision:  {best_row['precision']:.4f}")
        print(f"Accuracy:   {best_row['accuracy']:.4f}")

if __name__ == "__main__":
    main()
