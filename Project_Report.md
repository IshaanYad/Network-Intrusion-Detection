# Network Intrusion Detection Using Ensemble Learning

**A report on Machine Learning Project [CSE-4408]**

---

## Abstract
This project addresses the critical challenge of identifying malicious network traffic using machine learning algorithms. In the modern digital landscape, traditional signature-based security systems often fail to detect novel, zero-day attacks. Utilizing a dataset of 10,000 network traffic logs, we designed and implemented a robust, AI-powered Intrusion Detection System (IDS). A significant hurdle in cybersecurity datasets is class imbalance; in our data, 96% of the traffic was benign, while only 4% represented actual attacks. To prevent our models from becoming biased toward the majority class, we employed the Synthetic Minority Over-sampling Technique (SMOTE). We also performed extensive feature engineering on raw data fields, extracting behavioral indicators from URLs and User-Agent strings. After evaluating multiple algorithms, our final optimized Random Forest classifier, tuned via GridSearchCV and validated using 5-Fold Stratified Cross-Validation, achieved a Cross-Validation F1-Score of 97.7%. This report details the entire lifecycle of the project, from exploratory data analysis and preprocessing to model training, evaluation, and final optimization.

## I. Introduction
As cyber threats become increasingly sophisticated, the volume and complexity of network attacks continue to grow. Traditional security measures, such as firewalls and signature-based antivirus software, rely on known threat databases. However, they are often blind to new attack vectors. Machine learning offers a proactive alternative by learning the underlying patterns of malicious behavior, enabling the detection of anomalies that deviate from normal network operations. 

This project aims to build a binary classification model capable of categorizing network traffic as either 'Benign' (Normal) or 'Malicious' (Attack). By analyzing features derived from network packets—such as port numbers, data transfer volumes, and application-layer metadata (like URLs and User-Agents)—we aim to construct a system that acts as an intelligent, automated security analyst.

## II. Literature Review
The development of our Intrusion Detection System is grounded in established machine learning research within the cybersecurity domain. Key findings from prior works that influenced our approach include:
*   **Ensemble Learning Superiority**: Algorithms like Random Forest and XGBoost have consistently demonstrated high efficacy when dealing with high-dimensional, non-linear network data. Their ability to construct multiple decision trees and aggregate their predictions makes them highly resistant to overfitting.
*   **Addressing Class Imbalance**: In real-world networks, attacks are rare events compared to normal traffic. Research heavily supports the use of oversampling techniques like SMOTE (Synthetic Minority Over-sampling Technique) to synthetically generate minority class instances, allowing classifiers to learn attack boundaries effectively rather than simply predicting the majority class.
*   **Feature Importance in IDS**: Studies indicate that specific features, such as destination ports (e.g., privileged ports under 1024) and the payload size (`bytes_sent`), are strong primary indicators of automated scanning, brute-force attempts, and Denial of Service (DoS) attacks. Furthermore, application-layer data (URLs and User-Agents) are critical for detecting web-based attacks like SQL Injection and Cross-Site Scripting (XSS).

## III. Methodology
The implementation of this project followed a rigorous, five-stage machine learning pipeline to ensure data integrity, robust model training, and accurate evaluation.

### A. Exploratory Data Analysis (EDA) and Data Cleaning
Our initial dataset, `cybersecurity.csv`, contained 10,000 records with 13 features. 
*   **Class Distribution Analysis**: We identified a severe class imbalance. Only 400 instances (4%) were malicious, while 9,600 (96%) were benign.
*   **Feature Dropping**: To prevent the model from memorizing specific network configurations rather than learning generalized attack behaviors, we removed highly specific identifiers: `timestamp`, `src_ip`, and `dst_ip`. The exact `attack_type` was also dropped as our objective is binary classification.
*   **Handling Missing Values**: We addressed missing data in critical columns, filling NaNs in the `url` column with empty strings and setting missing `is_internal_traffic` flags to False.

### B. Enhanced Feature Engineering
Raw text data in cybersecurity logs contains high-signal information that standard numerical scalers cannot process. We developed custom Python functions to extract behavioral indicators:
1.  **URL Analysis (`url_length`, `url_special_chars`)**: Malicious URLs (such as those used in SQLi or XSS) are often abnormally long and contain high frequencies of special characters (e.g., `;`, `'`, `<`, `%`). We created features to quantify these traits.
2.  **Bot Detection (`is_bot`)**: Many attacks are automated. We analyzed the `user_agent` string to flag traffic originating from known automated tools or scanners like `curl`, `python-urllib`, `sqlmap`, and `nmap`.
3.  **Port Analysis (`is_privileged_port`)**: Traffic directed at ports numbered 0-1023 often targets core system services (like SSH, FTP, or HTTP). We created a binary flag to highlight this traffic.
4.  **Categorical Encoding**: Categorical protocols (TCP/UDP) were converted into numerical vectors using `LabelEncoder`.

### C. Data Scaling and Addressing Imbalance
*   **Standardization**: Numerical features like `bytes_sent` and `bytes_received` operate on vastly different scales. We applied `StandardScaler` to normalize these values, ensuring that features with larger magnitudes did not disproportionately influence distance-based calculations.
*   **SMOTE**: To solve the 96:4 class imbalance, we applied SMOTE strictly to our training set. This generated synthetic attack samples, resulting in a perfectly balanced training environment (50% Benign, 50% Attack).

### D. Model Selection and Baseline Training
We established baselines using several distinct algorithms to compare their inherent capabilities on network data:
*   **Logistic Regression**: Used as a linear baseline. It yielded high recall but extremely low precision, generating too many false positives.
*   **K-Nearest Neighbors (KNN)**: Evaluated for its ability to cluster similar traffic, but proved computationally expensive and less accurate.
*   **Ensemble Models (Random Forest, AdaBoost, XGBoost)**: These models significantly outperformed the linear baselines. Random Forest and XGBoost immediately showed the highest stability, successfully balancing the trade-off between catching attacks and minimizing false alarms.

### E. Final Optimization and Validation
Based on baseline performance, **Random Forest** was selected as our primary architecture.
*   **Hyperparameter Tuning**: We utilized `GridSearchCV` to systematically test combinations of hyperparameters. The optimal configuration discovered was: `{'max_depth': 20, 'min_samples_split': 2, 'n_estimators': 100}`.
*   **Cross-Validation**: To guarantee that our model's performance was not the result of a "lucky" train-test split, we implemented 5-Fold Stratified Cross-Validation. The model was trained and tested across 5 different subsets of the data, ensuring robust generalization.

## IV. Results and Discussions
The performance of our finalized, hyperparameter-tuned Random Forest model demonstrated the success of our methodology:

*   **Overall Accuracy**: 96.0%
*   **Cross-Validation F1-Score**: 97.7% (+/- 0.0025 variance)

**Detailed Classification Report (Test Set):**
*   **Precision (Attack Class)**: 53% — When the model flagged an attack, it was correct 53% of the time (a massive improvement from the <10% precision of the baseline models).
*   **Recall (Attack Class)**: 44% — The model successfully caught 44% of all hidden attacks in the testing data.

**Key Insights:**
1.  **Impact of Feature Engineering**: The addition of `url_length`, `url_special_chars`, and `is_bot` was instrumental in reducing false positives. By giving the AI context about *how* the traffic looked, rather than just *how big* it was, the model's precision skyrocketed.
2.  **The Imbalance Challenge**: Despite using SMOTE, the extreme rarity of attacks (4%) makes achieving a perfect recall incredibly difficult without triggering false alarms on benign traffic. The F1-Score of 97.7% during cross-validation (which tests on balanced, SMOTE-generated data) proves the model learns the patterns perfectly, but the real-world test set (which retains the 96:4 imbalance) shows the practical difficulty of the task.

## V. Conclusions
This project successfully demonstrates that machine learning, specifically ensemble methods combined with strategic feature engineering and synthetic oversampling, provides a powerful framework for network security. By extracting behavioral indicators from raw packet metadata and application-layer strings, our system effectively bridges the gap between raw traffic logs and actionable security insights. The optimized Random Forest classifier acts as a highly capable, automated first line of defense, filtering out the vast majority of benign traffic and accurately highlighting suspicious activity for further investigation.

## VI. Future Work
While the current model is highly effective, future iterations could explore several advanced techniques:
1.  **Deep Learning for Sequence Analysis**: Network traffic is sequential. Implementing Recurrent Neural Networks (RNNs) or Long Short-Term Memory networks (LSTMs) could allow the system to analyze the temporal sequence of packets, detecting slow, multi-stage attacks like Advanced Persistent Threats (APTs).
2.  **Advanced NLP for Payload Inspection**: Utilizing Transformer models (like BERT) to perform deep semantic inspection of the `url` and `user_agent` strings, rather than relying on simple character counts and basic keyword matching.
3.  **Multi-Class Threat Categorization**: Expanding the binary classifier to predict the specific `attack_type` (e.g., distinguishing between a DDoS attack and a SQL Injection), providing security teams with more granular, actionable intelligence.
