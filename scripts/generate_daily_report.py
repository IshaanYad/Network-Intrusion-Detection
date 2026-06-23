from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dynamic_evaluate import extract_features


DATASET_PATHS = [
    REPO_ROOT / "data" / "cybersecurity.csv",
    REPO_ROOT / "cybersecurity.csv",
]
LATEST_METRICS_PATH = REPO_ROOT / "outputs" / "latest_metrics.json"
EXPERIMENT_LOG_PATH = REPO_ROOT / "experiment_log.csv"
REPORTS_DIR = REPO_ROOT / "reports" / "daily"
README_PATH = REPO_ROOT / "README.md"

MODEL_NAME = "RandomForestClassifier"
TRAIN_FRACTION = 0.7
TEST_FRACTION = 0.3
THRESHOLD = 0.5
RANDOM_STATE = 42
REPORT_TIMEZONE = os.getenv("REPORT_TIMEZONE", "UTC")


def current_report_datetime() -> datetime:
    if REPORT_TIMEZONE.upper() == "UTC":
        return datetime.now(timezone.utc)
    return datetime.now(ZoneInfo(REPORT_TIMEZONE))


def resolve_dataset_path() -> Path:
    for path in DATASET_PATHS:
        if path.exists():
            return path
    raise FileNotFoundError("Could not find cybersecurity dataset in expected locations.")


def load_previous_metrics() -> dict | None:
    if not LATEST_METRICS_PATH.exists():
        return None
    return json.loads(LATEST_METRICS_PATH.read_text())


def evaluate_model(dataset_path: Path) -> dict:
    df = pd.read_csv(dataset_path)
    df = extract_features(df)

    cols_to_drop = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "user_agent",
        "url",
        "protocol",
        "attack_type",
        "label",
    ]
    X = df.drop(columns=cols_to_drop)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_FRACTION,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    smote = SMOTE(random_state=RANDOM_STATE)
    X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train_res, y_train_res)

    y_probs = model.predict_proba(X_test_scaled)[:, 1]
    y_pred = (y_probs >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    feature_importance = (
        pd.Series(model.feature_importances_, index=X.columns)
        .sort_values(ascending=False)
        .head(5)
    )

    return {
        "dataset_path": str(dataset_path.relative_to(REPO_ROOT)),
        "dataset_rows": int(len(df)),
        "attack_rate": round(float(y.mean()), 6),
        "train_fraction": TRAIN_FRACTION,
        "test_fraction": TEST_FRACTION,
        "threshold": THRESHOLD,
        "model": MODEL_NAME,
        "random_state": RANDOM_STATE,
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 6),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 6),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 6),
            "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 6),
        },
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "top_features": [
            {
                "feature": feature,
                "importance": round(float(importance), 6),
            }
            for feature, importance in feature_importance.items()
        ],
    }


def build_metrics_payload(results: dict, run_date: str, previous_metrics: dict | None) -> dict:
    generated_at = current_report_datetime().isoformat()
    deltas = {}
    if previous_metrics and "metrics" in previous_metrics:
        for key, value in results["metrics"].items():
            previous_value = previous_metrics["metrics"].get(key)
            if previous_value is not None:
                deltas[key] = round(value - float(previous_value), 6)

    payload = {
        "run_date": run_date,
        "generated_at": generated_at,
        "report_timezone": REPORT_TIMEZONE,
        "report_path": f"reports/daily/{run_date}.md",
        **results,
        "metric_deltas_vs_previous_run": deltas,
    }
    return payload


def update_experiment_log(metrics_payload: dict) -> None:
    row = {
        "date": metrics_payload["run_date"],
        "dataset_path": metrics_payload["dataset_path"],
        "model": metrics_payload["model"],
        "train_fraction": metrics_payload["train_fraction"],
        "test_fraction": metrics_payload["test_fraction"],
        "threshold": metrics_payload["threshold"],
        "accuracy": metrics_payload["metrics"]["accuracy"],
        "precision": metrics_payload["metrics"]["precision"],
        "recall": metrics_payload["metrics"]["recall"],
        "f1_score": metrics_payload["metrics"]["f1_score"],
        "true_negatives": metrics_payload["confusion_matrix"]["true_negatives"],
        "false_positives": metrics_payload["confusion_matrix"]["false_positives"],
        "false_negatives": metrics_payload["confusion_matrix"]["false_negatives"],
        "true_positives": metrics_payload["confusion_matrix"]["true_positives"],
        "top_features": ", ".join(
            feature["feature"] for feature in metrics_payload["top_features"]
        ),
    }

    if EXPERIMENT_LOG_PATH.exists():
        log_df = pd.read_csv(EXPERIMENT_LOG_PATH)
        log_df = log_df[log_df["date"] != row["date"]]
        log_df = pd.concat([log_df, pd.DataFrame([row])], ignore_index=True)
    else:
        log_df = pd.DataFrame([row])

    log_df = log_df.sort_values("date")
    log_df.to_csv(EXPERIMENT_LOG_PATH, index=False)


def metric_delta_line(metric_name: str, payload: dict) -> str:
    delta = payload["metric_deltas_vs_previous_run"].get(metric_name)
    if delta is None:
        return "n/a"
    return f"{delta:+.6f}"


def write_daily_report(metrics_payload: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"{metrics_payload['run_date']}.md"

    top_features = "\n".join(
        f"- `{feature['feature']}`: {feature['importance']:.6f}"
        for feature in metrics_payload["top_features"]
    )

    report = f"""# Daily IDS Evaluation Report - {metrics_payload['run_date']}

## Snapshot

| Metric | Value | Delta vs previous |
| :--- | :---: | :---: |
| Accuracy | {metrics_payload['metrics']['accuracy']:.6f} | {metric_delta_line('accuracy', metrics_payload)} |
| Precision | {metrics_payload['metrics']['precision']:.6f} | {metric_delta_line('precision', metrics_payload)} |
| Recall | {metrics_payload['metrics']['recall']:.6f} | {metric_delta_line('recall', metrics_payload)} |
| F1-Score | {metrics_payload['metrics']['f1_score']:.6f} | {metric_delta_line('f1_score', metrics_payload)} |

## Configuration

- Model: `{metrics_payload['model']}`
- Dataset: `{metrics_payload['dataset_path']}`
- Dataset rows: `{metrics_payload['dataset_rows']}`
- Attack rate: `{metrics_payload['attack_rate']:.6f}`
- Train/Test split: `{metrics_payload['train_fraction']:.1%}` / `{metrics_payload['test_fraction']:.1%}`
- Threshold: `{metrics_payload['threshold']}`
- Random state: `{metrics_payload['random_state']}`
- Generated at: `{metrics_payload['generated_at']}`
- Report timezone: `{metrics_payload['report_timezone']}`

## Confusion Matrix

| Outcome | Count |
| :--- | ---: |
| True Negatives | {metrics_payload['confusion_matrix']['true_negatives']} |
| False Positives | {metrics_payload['confusion_matrix']['false_positives']} |
| False Negatives | {metrics_payload['confusion_matrix']['false_negatives']} |
| True Positives | {metrics_payload['confusion_matrix']['true_positives']} |

## Top Features

{top_features}

## Notes

- This report is generated by `scripts/generate_daily_report.py`.
- `experiment_log.csv` is updated with one row per day for easy recruiter-facing experiment tracking.
- `outputs/latest_metrics.json` always reflects the most recent automated evaluation run.
"""
    report_path.write_text(report)


def update_readme(metrics_payload: dict) -> None:
    summary = f"""<!-- DAILY_SUMMARY_START -->
## Daily Evaluation Snapshot

| Metric | Latest Value |
| :--- | :---: |
| Last Run Date | {metrics_payload['run_date']} |
| Accuracy | {metrics_payload['metrics']['accuracy']:.6f} |
| Precision | {metrics_payload['metrics']['precision']:.6f} |
| Recall | {metrics_payload['metrics']['recall']:.6f} |
| F1-Score | {metrics_payload['metrics']['f1_score']:.6f} |
| Recommended Threshold | {metrics_payload['threshold']} |
| Split | 70 / 30 |

Latest artifacts: [Daily report](reports/daily/{metrics_payload['run_date']}.md), [Experiment log](experiment_log.csv), [Latest metrics JSON](outputs/latest_metrics.json)
<!-- DAILY_SUMMARY_END -->"""

    readme_text = README_PATH.read_text()
    start_marker = "<!-- DAILY_SUMMARY_START -->"
    end_marker = "<!-- DAILY_SUMMARY_END -->"

    if start_marker in readme_text and end_marker in readme_text:
        start_index = readme_text.index(start_marker)
        end_index = readme_text.index(end_marker) + len(end_marker)
        updated = readme_text[:start_index] + summary + readme_text[end_index:]
    else:
        insertion_point = readme_text.index("---\n\n## 📂 Project Structure")
        updated = readme_text[:insertion_point] + summary + "\n\n---\n\n" + readme_text[insertion_point + len("---\n\n"):]

    README_PATH.write_text(updated)


def main() -> None:
    run_date = current_report_datetime().date().isoformat()
    dataset_path = resolve_dataset_path()
    previous_metrics = load_previous_metrics()
    results = evaluate_model(dataset_path)
    metrics_payload = build_metrics_payload(results, run_date, previous_metrics)

    LATEST_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    LATEST_METRICS_PATH.write_text(json.dumps(metrics_payload, indent=2))
    update_experiment_log(metrics_payload)
    write_daily_report(metrics_payload)
    update_readme(metrics_payload)

    print(f"Wrote {LATEST_METRICS_PATH.relative_to(REPO_ROOT)}")
    print(f"Wrote {EXPERIMENT_LOG_PATH.relative_to(REPO_ROOT)}")
    print(f"Wrote reports/daily/{run_date}.md")
    print(f"Updated {README_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
