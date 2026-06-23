import matplotlib.pyplot as plt
import numpy as np

# Metrics for Threshold 0.3
metrics_03 = {
    'Accuracy': 93.10,
    'Precision (Attack)': 0.31,
    'Recall (Attack)': 0.57,
    'F1-score (Attack)': 0.40
}

# Metrics for Threshold 0.5
metrics_05 = {
    'Accuracy': 96.57,
    'Precision (Attack)': 0.59,
    'Recall (Attack)': 0.47,
    'F1-score (Attack)': 0.52
}

labels = list(metrics_03.keys())
x = np.arange(len(labels))
width = 0.35

fig, ax1 = plt.subplots(figsize=(10, 6))

# Accuracy is in %, others are 0-1. Let's normalize Accuracy to 0-1 for the same scale or use two axes.
# Actually, let's just use 0-1 scale and multiply precision/recall/f1 by 100 for percentage comparison.
vals_03 = [metrics_03[l] if l == 'Accuracy' else metrics_03[l]*100 for l in labels]
vals_05 = [metrics_05[l] if l == 'Accuracy' else metrics_05[l]*100 for l in labels]

rects1 = ax1.bar(x - width/2, vals_03, width, label='Threshold 0.3', color='skyblue')
rects2 = ax1.bar(x + width/2, vals_05, width, label='Threshold 0.5', color='salmon')

ax1.set_ylabel('Score (%)')
ax1.set_title('Model Performance Comparison: Threshold 0.3 vs 0.5')
ax1.set_xticks(x)
ax1.set_xticklabels(labels)
ax1.legend()
ax1.set_ylim(0, 110)

def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax1.annotate(f'{height:.1f}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

autolabel(rects1)
autolabel(rects2)

fig.tight_layout()
plt.savefig('outputs/threshold_comparison.png')
print("Comparison plot saved to outputs/threshold_comparison.png")

# Confusion Matrix Comparison
fig, ax2 = plt.subplots(figsize=(10, 6))
categories = ['True Positives', 'False Positives', 'False Negatives']
cm_03 = [69, 156, 51]
cm_05 = [56, 39, 64]

x_cm = np.arange(len(categories))
rects3 = ax2.bar(x_cm - width/2, cm_03, width, label='Threshold 0.3', color='skyblue')
rects4 = ax2.bar(x_cm + width/2, cm_05, width, label='Threshold 0.5', color='salmon')

ax2.set_ylabel('Count')
ax2.set_title('Detection Metrics Comparison: Threshold 0.3 vs 0.5')
ax2.set_xticks(x_cm)
ax2.set_xticklabels(categories)
ax2.legend()

autolabel(rects3)
autolabel(rects4)

fig.tight_layout()
plt.savefig('outputs/detection_metrics_comparison.png')
print("Detection metrics plot saved to outputs/detection_metrics_comparison.png")
