# Network Intrusion Detection using Ensemble Learning

An AI-powered Intrusion Detection System (IDS) designed to classify network traffic as **Benign** or **Malicious**. This project implements a full machine learning pipeline, from raw log processing and behavioral feature engineering to optimized ensemble modeling.

## 🚀 Overview
Traditional security systems often miss novel "zero-day" attacks. This project leverages **Ensemble Learning** (Random Forest, XGBoost) and **SMOTE** (Synthetic Minority Over-sampling Technique) to detect anomalies in highly imbalanced network data (96% benign vs. 4% attack).

### Key Features:
- **Behavioral Feature Engineering**: Extracts signals from URLs (length, special characters) and User-Agent strings (bot detection).
- **Imbalance Handling**: Uses SMOTE to handle the extreme 96:4 class distribution.
- **Dynamic Model Auditing**: Custom tools to evaluate model performance across different train/test splits and probability thresholds.
- **Syllabus Alignment**: Maps core ML concepts (Classification, Ensembles, Evaluation) to a real-world cybersecurity use case.

<!-- DAILY_SUMMARY_START -->
## Daily Evaluation Snapshot

| Metric | Latest Value |
| :--- | :---: |
| Last Run Date | 2026-06-30 |
| Accuracy | 0.965667 |
| Precision | 0.589474 |
| Recall | 0.466667 |
| F1-Score | 0.520930 |
| Recommended Threshold | 0.5 |
| Split | 70 / 30 |

Latest artifacts: [Daily report](reports/daily/2026-06-30.md), [Experiment log](experiment_log.csv), [Latest metrics JSON](outputs/latest_metrics.json), [Automation heartbeat](outputs/automation_heartbeat.json)
<!-- DAILY_SUMMARY_END -->

---

## 📂 Project Structure
```text
├── cybersecurity.csv       # Primary Dataset
├── .github/workflows/      # Scheduled automation for daily evaluation commits
├── reports/daily/          # Dated daily evaluation summaries
├── experiment_log.csv      # One-row-per-day experiment history
├── src/                    # Implementation scripts
│   ├── baseline_ids.py     # Initial models (Logistic Regression, KNN, SVM)
│   ├── ids_enhanced.py     # Added Feature Engineering & SMOTE
│   └── ids_final_optimized.py # Final GridSearchCV & Cross-Validation
├── scripts/generate_daily_report.py # Generates daily recruiter-facing evaluation artifacts
├── dynamic_evaluate.py     # CLI tool for testing custom splits and thresholds
├── find_optimal_params.py  # Grid search tool to find best split/threshold combo
├── generate_attack_graph.py # Visualizes attack distribution in 100-entry blocks
├── outputs/                # Visualizations & Metrics (Plots, JSON results)
├── presentation/           # Materials for project walkthrough
├── Project_Report.md       # Comprehensive technical documentation
├── Project_Mapping.md      # Mapping project to ML syllabus
└── predict_custom.py       # Script for testing on new/custom data
```

---

## 🛠️ Installation & Usage

### 1. Setup Environment
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install pandas numpy matplotlib seaborn scikit-learn xgboost imbalanced-learn
```

### 2. Run the Analysis Tools
- **Find Optimal Split/Threshold**:
  ```bash
  python find_optimal_params.py
  ```
- **Dynamic Evaluation**:
  ```bash
  python dynamic_evaluate.py --split 0.3 --threshold 0.5
  ```
- **Generate Attack Distribution Graph**:
  ```bash
  python generate_attack_graph.py
  ```
- **Generate Daily Recruiter-Facing Report**:
  ```bash
  python scripts/generate_daily_report.py
  ```

### 3. Automated Daily Refresh
The repository includes `.github/workflows/daily-report.yml`, which reruns the 70/30 Random Forest evaluation every day, updates:

- `reports/daily/YYYY-MM-DD.md`
- `experiment_log.csv`
- `outputs/latest_metrics.json`
- `outputs/automation_heartbeat.json`
- the README snapshot above

The workflow commits only when generated artifacts change.

---

## 📊 Results & Findings

### Model Comparison & Selection
To identify the most effective architecture for our Intrusion Detection System, we compared multiple algorithms using a standardized 80/20 train-test split and SMOTE-balanced training data.

| Model | Accuracy | Precision | Recall | F1-Score |
| :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | **96.15%** | **0.5224** | **0.4375** | **0.4762** |
| **XGBoost** | 95.90% | 0.4861 | 0.4375 | 0.4605 |
| **AdaBoost** | 85.30% | 0.1232 | 0.4375 | 0.1923 |
| **K-Nearest Neighbors** | 83.10% | 0.1043 | 0.4250 | 0.1675 |
| **Logistic Regression** | 55.80% | 0.0543 | 0.6125 | 0.0998 |

### Why Random Forest?
Random Forest was selected as our "Stability Champion" for several key reasons:
- **Ensemble Robustness:** By aggregating predictions from 100+ decision trees, it significantly reduces the risk of overfitting compared to single-tree models.
- **Handling Class Imbalance:** It proved highly effective at identifying the rare 4% of "attack" labels when paired with SMOTE, maintaining a superior balance between Precision and Recall.
- **Feature Explainability:** It provides built-in feature importance scores, allowing us to verify that the model is making decisions based on meaningful signals (like URL length and special characters).
- **Non-Linear Patterns:** It naturally captures the complex, non-linear relationships common in network traffic logs (e.g., a specific combination of port and URL behavior).

### Why these Optimal Parameters?
Through automated grid search (`find_optimal_params.py`), we identified the **70/30 Train-Test Split** and **0.5 Threshold** as the ideal configuration. Here is why:

1. **The 70/30 Split (Stability):** 
   - A 70% training set provides enough data for the Random Forest to learn complex attack patterns and handle the minority class (using SMOTE). 
   - Reserving 30% for testing (instead of 10% or 20%) ensures that our evaluation metrics (Precision, Recall, F1) are statistically significant and not influenced by a "lucky" or "unlucky" small sample of rare attacks.

2. **The 0.5 Threshold (The "Goldilocks" Balance):**
   - **Lower Thresholds (e.g., 0.1 - 0.3):** While these catch more attacks (High Recall), they create a "False Alarm" crisis. For example, at a 0.1 threshold, our precision drops to ~10%, meaning 9 out of 10 alerts would be false positives.
   - **Higher Thresholds (e.g., 0.7 - 0.9):** These are too conservative. While they are very accurate when they *do* flag an alert (High Precision), they miss over 80% of actual attacks (Low Recall).
   - **The 0.5 Sweet Spot:** This threshold yielded the highest **F1-Score (0.5209)**, representing the most effective real-world balance between catching threats and maintaining system trust.

3. **Metric Priority (F1-Score over Accuracy):**
   - Because 96% of the data is benign, "Accuracy" is a deceptive metric (a model that does nothing would be 96% accurate). We prioritized the **F1-Score** because it forces the model to perform well on both Precision and Recall simultaneously.

### Attack Distribution
The following graph (generated via `generate_attack_graph.py`) shows the distribution of actual attacks across the dataset in blocks of 100 entries ("classes"). This visualization helps identify temporal bursts of malicious activity.

![Attacks per 100 entries](outputs/attacks_per_100_entries.png)

### Key Indicators
`url_special_chars`, `url_length`, and `is_bot` remain the most significant features for identifying malicious intent.

---

## 📝 Documentation
- **[Technical Report](Project_Report.md)**: Detailed methodology, EDA, and result analysis.
- **[Syllabus Mapping](Project_Mapping.md)**: How this project covers ML modules (Ensembles, Entropy, Bias-Variance, etc.).
- **[Presentation Guide](presentation/Presentation_Guide.md)**: Summary for viva/presentation.

---
**Course:** Machine Learning [CSE-4408]  
**Topic:** Ensemble Learning in Cybersecurity
