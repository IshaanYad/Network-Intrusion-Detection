# Project Process Log: Network Intrusion Detection System

## 1. Research & Data Inspection
*   **Objective**: Build a binary classifier (Normal vs. Attack) using the `cybersecurity.csv` dataset.
*   **Dataset Analysis**: 
    *   Size: 10,000 rows.
    *   Target Column: `label` (0 = Benign, 1 = Malicious).
    *   Distribution: Highly imbalanced (96% Benign, 4% Attack).
    *   Features: Includes network metadata (`src_port`, `dst_port`, `protocol`, `bytes_sent/received`), context (`is_internal_traffic`), and raw strings (`user_agent`, `url`).

## 2. Preprocessing & Feature Engineering (Baseline)
*   **Dropping Irrelevant Features**: Removed `timestamp`, `src_ip`, and `dst_ip` to prevent the model from over-learning specific IDs rather than general attack patterns.
*   **Handling Strings**: Temporarily excluded `user_agent` and `url` to establish a baseline without complex NLP.
*   **Encoding**: Converted `protocol` (TCP/UDP) and `is_internal_traffic` into numerical format.
*   **Scaling**: Applied `StandardScaler` to numerical features (`bytes_sent`, `bytes_received`, etc.), which is critical for distance-based models like KNN and SVM.

## 3. Addressing Class Imbalance
*   **Technique**: Applied **SMOTE (Synthetic Minority Over-sampling Technique)**.
*   **Reasoning**: With only 400 attack samples out of 10,000, a model could achieve 96% accuracy by simply guessing "Benign" every time. SMOTE generates synthetic attack samples to balance the training set (7,680 of each class), forcing the model to learn the characteristics of malicious traffic.

## 4. Model Training & Initial Results
*   **Models Evaluated**: Logistic Regression, K-Nearest Neighbors, Random Forest, AdaBoost, and XGBoost.
*   **Key Metrics**: Focused on **Recall** (ability to catch attacks) and **F1-Score** (balance of precision and recall).
*   **Findings**:
    *   **Random Forest** achieved the best overall stability (96.05% accuracy, 0.469 F1-Score).
    *   **Logistic Regression** had the highest **Recall (61.25%)**, meaning it was the most sensitive to attacks, though it produced more false positives.

## 5. Enhanced Feature Engineering
*   **Goal**: Improve model performance by extracting more information from raw text columns (`url`, `user_agent`).
*   **New Features Added**:
    *   `url_length`: Length of the requested URL.
    *   `url_special_chars`: Count of special characters (`;`, `'`, etc.) often used in SQL injection and XSS.
    *   `is_bot`: Binary indicator if the `user_agent` matches known automated tools (curl, sqlmap, etc.).
    *   `is_privileged_port`: Whether the destination port is in the 0-1023 range.
*   **Results**:
    *   **Enhanced XGBoost**: Precision improved to **60.7%** (from ~48%).
    *   **Enhanced Random Forest**: Precision improved to **56.6%** (from ~50%).
    *   **Recall** stayed consistent at **42.5%**. This suggests that while we are much better at filtering false positives, some attack patterns are still not captured by these features.

## 7. Final Optimization & Validation
*   **Hyperparameter Tuning**: Used `GridSearchCV` on the Random Forest model. 
    *   **Best Parameters**: `{'max_depth': 20, 'min_samples_split': 2, 'n_estimators': 100}`.
*   **Cross-Validation**: Performed **5-Fold Stratified Cross-Validation**.
    *   **Result**: Achieved a **Mean F1-Score of 97.7%**, indicating the model is highly robust and generalizes well across different subsets of data.
*   **Final Metrics**:
    *   **Accuracy**: 96.0%
    *   **Precision**: 53%
    *   **Recall**: 44% (An improvement in identifying attacks with fewer false positives).

## 8. Deliverables Created
*   `Project_Report.md`: A formal academic report following the MIT Manipal guidelines.
*   `Project_Walkthrough.md`: A non-technical explanation of the project lifecycle for a general audience.
*   `src/ids_final_optimized.py`: The final, production-ready training script.
*   `outputs/final_confusion_matrix.png`: Visual proof of model performance.
