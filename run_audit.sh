#!/bin/bash

# run_audit.sh - Automated IDS Model Audit Script

# 1. Setup Audit Directory
mkdir -p 90_10_model_audit
cp data/cybersecurity.csv 90_10_model_audit/

# 2. Activate Virtual Environment
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install pandas scikit-learn xgboost imbalanced-learn seaborn matplotlib
fi

# 3. Execute the Audit
echo "Starting the 90/10 Model Audit..."
cd 90_10_model_audit
python3 evaluate_split.py

# 4. Cleanup or Finish
echo "Audit complete."
