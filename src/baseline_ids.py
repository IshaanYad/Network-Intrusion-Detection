import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE
import warnings

warnings.filterwarnings('ignore')

# 1. Data Loading & EDA
print("--- Step 1: Loading Data & EDA ---")
df = pd.read_csv('cybersecurity.csv')

print(f"Dataset Shape: {df.shape}")
print("\nMissing Values:")
print(df.isnull().sum())

print("\nClass Distribution (0 = Benign, 1 = Attack):")
print(df['label'].value_counts(normalize=True))

# 2. Preprocessing & Feature Engineering
print("\n--- Step 2: Preprocessing ---")

# Drop high-cardinality and irrelevant columns for the baseline
# timestamp, src_ip, dst_ip are too specific for a general model
# user_agent and url would require NLP (TF-IDF/Embeddings) which is out of scope for a basic IDS model
cols_to_drop = ['timestamp', 'src_ip', 'dst_ip', 'user_agent', 'url', 'attack_type']
df_clean = df.drop(columns=cols_to_drop)

# Handle missing values
# is_internal_traffic might have NaNs based on preview
df_clean['is_internal_traffic'] = df_clean['is_internal_traffic'].fillna(False).astype(int)

# Encode Categorical Features
le = LabelEncoder()
df_clean['protocol'] = le.fit_transform(df_clean['protocol'].astype(str))

# Define Features and Target
X = df_clean.drop('label', axis=1)
y = df_clean['label']

# Split Data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Scale Features (Critical for KNN, SVM, Logistic Regression)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Handle Imbalance using SMOTE
print("Applying SMOTE to balance the training set...")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
print(f"New Class Distribution: {pd.Series(y_train_res).value_counts().to_dict()}")

# 3. Model Training & Evaluation
print("\n--- Step 3: Model Training & Evaluation ---")

models = {
    "Logistic Regression": LogisticRegression(),
    "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "AdaBoost": AdaBoostClassifier(random_state=42),
    "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
}

results = []

for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train_res, y_train_res)
    y_pred = model.predict(X_test_scaled)
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    results.append({
        "Model": name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-Score": f1
    })
    
    print(f"{name} Results:")
    print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
    print(f"Recall: {rec:.4f} (Crucial for IDS to catch all attacks)")
    print("-" * 30)

# 4. Comparison
print("\n--- Step 4: Final Comparison ---")
results_df = pd.DataFrame(results).sort_values(by='F1-Score', ascending=False)
print(results_df)

# Save results to a CSV for the report
results_df.to_csv('model_comparison_results.csv', index=False)
print("\nComparison results saved to 'model_comparison_results.csv'")

# Visualization of Results
plt.figure(figsize=(10, 6))
sns.barplot(x='F1-Score', y='Model', data=results_df, palette='viridis')
plt.title('Model Comparison - F1-Score')
plt.savefig('model_comparison_plot.png')
print("Comparison plot saved as 'model_comparison_plot.png'")
