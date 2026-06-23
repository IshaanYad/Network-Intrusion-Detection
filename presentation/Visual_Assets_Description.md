# Visual Assets Guide for NIDS Presentation

Use this document to create or select images for your slides.

---

## Asset 1: The Imbalance (Slide 2)
**Image Description:** A high-contrast Pie Chart.
- **Slice A (96%):** Soft Green, labeled "Benign / Normal Traffic".
- **Slice B (4%):** Bright Red, labeled "Malicious / Attacks".
- **Caption:** 10,000 logs total. The challenge: Catching the 4% needle in the 96% haystack.

---

## Asset 2: Feature Engineering (Slide 4)
**Image Description:** Three side-by-side icons with labels.
- **Icon 1:** A robot face. Label: `is_bot` (Regex-based User-Agent scan).
- **Icon 2:** A magnifying glass over a URL. Label: `url_special_chars` (SQLi/XSS detection).
- **Icon 3:** A network cable plugged into a locked port. Label: `is_privileged_port` (System service monitoring).

---

## Asset 3: SMOTE Explanation (Slide 5)
**Image Description:** A two-panel diagram.
- **Left Panel:** "Actual Data". A few red dots (attacks) scattered among many green dots (normal).
- **Right Panel:** "With SMOTE". New "hollow" red dots appear along the lines connecting the original red dots.
- **Label:** Synthetic Minority Over-sampling Technique (SMOTE).

---

## Asset 4: Final Confusion Matrix (Slide 7)
**Image Description:** Use the actual project output: `outputs/final_confusion_matrix.png`.
- **Top-Left (True Negative):** High number (e.g., 1800+).
- **Bottom-Right (True Positive):** The number of successfully caught attacks.
- **Top-Right (False Positive):** The "False Alarms".
- **Bottom-Left (False Negative):** The "Missed Attacks".

---

## Asset 5: Performance Leaderboard (Slide 6)
**Image Description:** A vertical bar chart or horizontal leaderboard.
- **Metrics to compare:** F1-Score or Precision.
- **Competitors:** Logistic Regression, KNN, XGBoost, Random Forest (Winner).
- **Highlight:** Use a gold crown or star next to Random Forest.

---

## Asset 6: Live Demo Visualization (Slide 8)
**Image Description:** A screenshot of a terminal window.
- **Command shown:** `python predict_custom.py blind_test.csv`
- **Output shown:** Several lines of `[BENIGN]` followed by one bright red `!!! [ATTACK] !!!`.
- **Purpose:** To give the audience a preview of what they are about to see live.
