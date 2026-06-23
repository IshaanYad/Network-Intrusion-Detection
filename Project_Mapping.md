# Project Plan: Network Intrusion Detection Using Ensemble Learning

This document maps the concepts from the **Machine Learning Syllabus** to the specific tasks and implementation details of the **Cybersecurity Network Intrusion Detection** project.

---

## 1. Core Problem Definition
**Objective:** Binary Classification (Normal Traffic vs. Malicious Attack)
**Dataset:** `cybersecurity.csv`

---

## 2. Syllabus Topics to Apply

### A. Classification Algorithms (Syllabus: Module 1, 2, 3)
*   **Logistic Regression:** Use as a baseline model to predict the probability of an attack (`label`).
*   **K-Nearest Neighbors (KNN):** Identify malicious traffic by finding similar patterns in `src_port`, `dst_port`, and `bytes_sent`.
*   **Support Vector Machines (SVM):** Useful for finding the optimal hyperplane that separates benign and malicious traffic in a high-dimensional feature space.
*   **Perceptron / ANN:** Implement a basic neural network to capture non-linear relationships between traffic features.

### B. Ensemble Learning (Syllabus: Module 6)
*   **Bagging (Random Forest):** Use to reduce variance and improve the stability of your predictions across different types of network traffic.
*   **Boosting (AdaBoost & XGBoost):** Focus on "hard-to-classify" attack types by iteratively training models on the residuals of previous ones.
*   **Voting/Stacking:** Combine the predictions of Logistic Regression, KNN, and SVM to create a more robust "Meta-Classifier."

### C. Feature Engineering & Preprocessing (Syllabus: Module 1.2, 1.3)
*   **Entropy & Information Gain:** Use these to perform feature selection. Determine which features (e.g., `protocol`, `dst_port`) provide the most information for predicting the `label`.
*   **Handling Bias and Weights:** If the dataset is imbalanced (more benign traffic than attacks), apply weights to the "Attack" class during training.
*   **Normalization/Scaling:** Essential for algorithms like KNN and SVM that are sensitive to the scale of features like `bytes_sent`.

### D. Model Evaluation (Syllabus: Module 06)
*   **Confusion Matrix:** The primary tool for evaluating your model's performance.
    *   **True Positives (TP):** Correctly identified attacks.
    *   **False Negatives (FN):** Missed attacks (High risk in cybersecurity).
    *   **False Positives (FP):** Benign traffic flagged as an attack.
*   **Parameters:** Calculate **Accuracy**, **Precision**, **Recall**, and **F1-Score**.
*   **Bias-Variance Trade-off:** Analyze if your model is underfitting or overfitting the training data.

---

## 3. Implementation Roadmap

1.  **Data Loading & EDA:** Load `cybersecurity.csv` and check for missing values and class imbalance in the `label` column.
2.  **Preprocessing:** 
    *   Convert `protocol` (TCP/UDP) and `is_internal_traffic` to numerical values.
    *   Scale `bytes_sent` and `bytes_received`.
3.  **Model Training:** Train individual models (Logistic Regression, KNN, SVM) and then the Ensemble models (Random Forest, AdaBoost).
4.  **Comparison:** Use a **Confusion Matrix** to compare the performance of each model.
5.  **Conclusion:** Summarize which model performed best for detecting network intrusions.
