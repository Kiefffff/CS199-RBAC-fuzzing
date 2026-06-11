import pandas as pd
from scipy.stats import mannwhitneyu, spearmanr
import numpy as np

def cliffs_delta(x, y):
    """Calculate Cliff's Delta effect size."""
    n_x, n_y = len(x), len(y)
    greater = less = ties = 0
    
    for xi in x:
        for yj in y:
            if yj > xi:
                greater += 1
            elif yj < xi:
                less += 1
            else:
                ties += 1
    
    total = n_x * n_y
    delta = (greater - less) / total
    
    # Interpretation
    if abs(delta) < 0.147:
        interp = "Negligible"
    elif abs(delta) < 0.33:
        interp = "Small"
    elif abs(delta) < 0.474:
        interp = "Medium"
    else:
        interp = "Large"
    
    return delta, interp

if __name__ == "__main__":
    # Load your data
    run_summary = pd.read_csv('data/run-summary.csv')
    
    # Extract detections
    generic = run_summary[run_summary['Fuzzer'] == 'ZAP']['BAC True Positives'].tolist()
    stateaware = run_summary[run_summary['Fuzzer'].isin(['Schemathesis', 'EvoMaster'])]['BAC True Positives'].tolist()
    
    # Calculate Cliff's Delta
    delta, interpretation = cliffs_delta(generic, stateaware)
    
    # Mann-Whitney U
    u_stat, p_value = mannwhitneyu(generic, stateaware, alternative='two-sided')
    
    # Spearman correlation
    runtime = run_summary['Duration (s)'].astype(str).str.replace('~', '').str.replace(',', '').astype(float)
    detections = run_summary['BAC True Positives'].astype(float)
    rho, p_corr = spearmanr(runtime, detections)
    
    print(f"=== STATISTICAL ANALYSIS ===")
    print(f"Cliff's Delta (δ): {delta:.3f} ({interpretation} effect)")
    print(f"Mann-Whitney U: {u_stat}, p-value: {p_value:.3f}")
    print(f"Spearman's ρ: {rho:.3f}, p-value: {p_corr:.3f}")