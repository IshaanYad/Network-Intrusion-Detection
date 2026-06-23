import pandas as pd
import matplotlib.pyplot as plt
import os

# Load the dataset
df = pd.read_csv('cybersecurity.csv')

# Determine the attack indicator
# We'll use the 'label' column. If it's mixed, we'll try to normalize it.
# Based on inspection, label 1 or non-benign attack_type are attacks.

def is_attack(row):
    # Normalize label to boolean
    label = str(row['label']).lower()
    if label in ['1', '1.0', 'true']:
        return True
    if label in ['0', '0.0', 'false']:
        return False
    # Fallback to attack_type
    attack_type = str(row['attack_type']).lower()
    if attack_type != 'benign' and attack_type != '0':
        return True
    return False

df['is_attack'] = df.apply(is_attack, axis=1)

# Group into blocks of 100
df['block'] = df.index // 100
attack_counts = df.groupby('block')['is_attack'].sum()

# Plot
plt.figure(figsize=(15, 6))
plt.bar(attack_counts.index, attack_counts.values, color='red', alpha=0.7)
plt.title('Number of Attacks per 100 Entries')
plt.xlabel('Block Index (Each block is 100 entries)')
plt.ylabel('Number of Attacks')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()

# Save the plot
output_path = 'outputs/attacks_per_100_entries.png'
plt.savefig(output_path)
print(f"Graph saved to {output_path}")

# Also print some stats
print(f"Total blocks: {len(attack_counts)}")
print(f"Max attacks in a block: {attack_counts.max()}")
print(f"Min attacks in a block: {attack_counts.min()}")
print(f"Average attacks per block: {attack_counts.mean():.2f}")
