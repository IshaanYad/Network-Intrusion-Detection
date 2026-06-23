# Model Testing & Validation Guide

This guide explains how to verify and audit the Network Intrusion Detection System (NIDS).

---

## 1. Prerequisites
Ensure all required machine learning libraries are installed:
```bash
pip install pandas scikit-learn xgboost imbalanced-learn seaborn matplotlib
```

---

## 2. Option A: Full Pipeline Validation
To run the complete training, hyperparameter tuning, and 5-Fold Cross-Validation, use the optimized production script. This will generate a performance report and a confusion matrix.

**Command:**
```bash
python3 src/ids_final_optimized.py
```

**What to check in `outputs/`:**
*   **`final_metrics.json`**: Check for a **Cross-Validation F1-Score** above 95%.
*   **`final_confusion_matrix.png`**: Look for high numbers in the "True Positive" (bottom-right) and "True Negative" (top-left) quadrants.

---

## 3. Option B: Testing with Custom Data (Blind Audit)
To test the model against a specific set of traffic logs (like your own custom-made attacks), use the `predict_custom.py` script.

**Command:**
```bash
python3 predict_custom.py <your_test_file.csv>
```

### Required CSV Format:
Your test CSV must contain these columns (even if they are empty/None):
`timestamp, src_ip, dst_ip, protocol, src_port, dst_port, bytes_sent, bytes_received, is_internal_traffic, user_agent, url`

### Interpreting the Results:
*   **`[BENIGN]`**: The model identified the traffic as normal user activity.
*   **`!!! [ATTACK] !!!`**: The model detected a high-probability security threat.

---

## 4. Understanding the "Blind Test" Results
When testing with `blind_test.csv`, the model successfully identified the following:

| Entry | Attack Type | Behavioral Trigger | Result |
| :--- | :--- | :--- | :--- |
| **2** | SQL Injection | Detected `' OR '1'='1'` and high `url_special_chars`. | **PASSED** |
| **4** | Port Scan | Identified the `nmap` tool in the `user_agent`. | **PASSED** |
| **5** | XSS | Caught `<script>` tags in the URL string. | **PASSED** |
| **7** | SQL Injection | Detected the `sqlmap` automated attack tool. | **PASSED** |
| **9** | Exfiltration | Identified abnormally high `bytes_sent` (50MB). | **PASSED** |
| **10** | Path Traversal | Flagged the attempt to access `/etc/passwd`. | **PASSED** |

---

## 5. Troubleshooting
*   **ModuleNotFoundError**: Ensure you are using `python3` and have run the `pip install` command.
*   **Column Mismatch**: If you use a custom CSV, ensure the column names match the original `cybersecurity.csv` headers exactly.
