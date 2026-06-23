# Key Code Snippets for Presentation

Copy-paste these snippets directly into your slides or use them during live coding/demo segments.

---

### 1. Custom Feature Engineering (The "Secret Sauce")
This function transforms raw logs into security-aware data.
```python
def extract_features(df):
    # Analyzing URL behavioral patterns
    df['url_length'] = df['url'].fillna('').apply(len)
    df['url_special_chars'] = df['url'].fillna('').apply(
        lambda x: len(re.findall(r"[;'\"<>%&?]", x))
    )
    
    # Automated Tool (Bot) Detection
    bots = ['curl', 'python-urllib', 'sqlmap', 'nmap']
    df['is_bot'] = df['user_agent'].str.lower().apply(
        lambda x: 1 if any(bot in x for bot in bots) else 0
    )
    
    # Critical System Port Monitoring
    df['is_privileged_port'] = df['dst_port'].apply(
        lambda x: 1 if x < 1024 else 0
    )
```

---

### 2. Balancing the Dataset (SMOTE)
Ensuring the model doesn't ignore the minority class.
```python
from imblearn.over_sampling import SMOTE

# Initial ratio was 96:4 (Normal:Attack)
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

# Resulting ratio is 50:50 (Perfectly Balanced)
```

---

### 3. Hyperparameter Optimization
Fine-tuning the "winner" (Random Forest).
```python
from sklearn.model_selection import GridSearchCV

rf_param_grid = {
    'n_estimators': [50, 100],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5]
}

rf_grid = GridSearchCV(RandomForestClassifier(), rf_param_grid, cv=3, scoring='f1')
rf_grid.fit(X_train_res, y_train_res)

print(f"Best Parameters: {rf_grid.best_params_}")
```

---

### 4. Robust Validation (5-Fold Cross-Validation)
Proving the model is reliable across different data subsets.
```python
from sklearn.model_selection import cross_val_score, StratifiedKFold

skf = StratifiedKFold(n_splits=5, shuffle=True)
cv_scores = cross_val_score(best_rf, X_train_res, y_train_res, cv=skf, scoring='f1')

print(f"Final Mean F1-Score: {cv_scores.mean():.4f}")
# Output: 0.9770 (97.7%)
```

---

### 5. Prediction CLI (Live Demo Snippet)
The entry point for real-world testing.
```python
# To run in terminal:
# python predict_custom.py blind_test.csv

X_test_scaled = scaler.transform(processed_custom_data)
predictions = model.predict(X_test_scaled)

for pred in predictions:
    status = "!!! [ATTACK] !!!" if pred == 1 else "[BENIGN]"
    print(status)
```
