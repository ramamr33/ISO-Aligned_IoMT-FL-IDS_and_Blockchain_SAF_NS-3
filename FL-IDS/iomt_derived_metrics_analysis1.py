import pandas as pd
import numpy as np
from scipy import stats
from scipy.stats import mannwhitneyu, pearsonr, t as t_dist
import seaborn as sns
import matplotlib.pyplot as plt

# Your data from Table 1
data = {
    'Device': ['WIP']*9 + ['SHS']*9,
    'FlowID': list(range(1,10)) + list(range(1,10)),
    'TRR': [99.85478, 97.61162, 75.10531, 86.91208, 86.91867, 86.9141, 86.92891, 86.92139, 100,
            99.85118, 97.55239, 74.48798, 86.58753, 86.59428, 86.5896, 86.60478, 86.59707, 100],
    'PLR': [0, 73.54218, 24.72079, 57.58044, 71.1419, 73.20745, 80.97754, 74.48699, 0,
            0, 73.54218, 28.58367, 66.57798, 82.25857, 78.96341, 92.91776, 86.12636, 0],
    'NDI': [100, 26.45782, 75.27921, 42.41956, 28.8581, 26.79255, 19.02246, 25.51301, 100,
            100, 26.45782, 71.41633, 33.42202, 17.74143, 21.03659, 7.082243, 13.87364, 100],
    'JVI': [100, 100, 58.04196, 31.59592, 11.4695, 8.892594, 2.165915, 0.408559, 100,
            100, 100, 39.75095, 19.4359, 4.081265, 8.892594, 2.165915, 0.408559, 100],
    'ASI': [69.94191, 54.33621, 51.48356, 49.62262, 48.90826, 41.83815, 51.64979, 49.21434, 100,
            79.97024, 57.44782, 48.41965, 34.20611, 26.1, 26.84651, 24.22032, 24.35402, 100]
}

df = pd.DataFrame(data)

def test_normality(data, device, metric):
    """Test if data is normally distributed using Shapiro-Wilk test"""
    device_data = data[data['Device'] == device][metric]
    stat, p_value = stats.shapiro(device_data)
    is_normal = p_value > 0.05
    return is_normal, p_value

# Test normality for all metrics
metrics = ['TRR', 'PLR', 'NDI', 'JVI', 'ASI']
normality_results = []

for metric in metrics:
    wip_normal, wip_p = test_normality(df, 'WIP', metric)
    shs_normal, shs_p = test_normality(df, 'SHS', metric)
    
    normality_results.append({
        'Metric': metric,
        'WIP_Normal': wip_normal,
        'WIP_p_value': wip_p,
        'SHS_Normal': shs_normal,
        'SHS_p_value': shs_p,
        'Both_Normal': wip_normal and shs_normal
    })

normality_df = pd.DataFrame(normality_results)
print("Normality Test Results (Shapiro-Wilk):")
print(normality_df)

def compare_devices(data, metric):
    """
    Compare WIP vs SHS for a given metric.
    Uses t-test if both normal, otherwise Mann-Whitney U test.
    """
    wip_data = data[data['Device'] == 'WIP'][metric].values
    shs_data = data[data['Device'] == 'SHS'][metric].values
    
    # Check normality
    wip_normal = stats.shapiro(wip_data)[1] > 0.05
    shs_normal = stats.shapiro(shs_data)[1] > 0.05
    both_normal = wip_normal and shs_normal
    
    # Perform appropriate test
    if both_normal:
        # Independent samples t-test
        statistic, p_value = stats.ttest_ind(wip_data, shs_data)
        test_used = "Independent t-test"
    else:
        # Mann-Whitney U test
        statistic, p_value = mannwhitneyu(wip_data, shs_data, alternative='two-sided')
        test_used = "Mann-Whitney U"
    
    # Effect size (Cohen's d for t-test, rank-biserial for Mann-Whitney)
    if both_normal:
        pooled_std = np.sqrt(((len(wip_data)-1)*np.var(wip_data, ddof=1) + 
                             (len(shs_data)-1)*np.var(shs_data, ddof=1)) / 
                            (len(wip_data) + len(shs_data) - 2))
        effect_size = (np.mean(wip_data) - np.mean(shs_data)) / pooled_std
        effect_type = "Cohen's d"
    else:
        # Rank-biserial correlation for Mann-Whitney
        U = statistic
        n1, n2 = len(wip_data), len(shs_data)
        effect_size = 1 - (2*U) / (n1 * n2)
        effect_type = "Rank-biserial"
    
    return {
        'Metric': metric,
        'WIP_Mean': np.mean(wip_data),
        'WIP_Median': np.median(wip_data),
        'SHS_Mean': np.mean(shs_data),
        'SHS_Median': np.median(shs_data),
        'Test_Used': test_used,
        'Statistic': statistic,
        'p_value': p_value,
        'Significant': p_value < 0.05,
        'Effect_Size': effect_size,
        'Effect_Type': effect_type
    }

# Run comparison for all metrics
comparison_results = []
for metric in metrics:
    result = compare_devices(df, metric)
    comparison_results.append(result)

comparison_df = pd.DataFrame(comparison_results)
print("\nComparative Analysis (WIP vs SHS):")
print(comparison_df.to_string())

def calculate_correlations(data):
    """Calculate Pearson correlation coefficients between all metric pairs"""
    metrics = ['TRR', 'PLR', 'NDI', 'JVI']  # Exclude ASI since it's derived from these
    
    correlations = []
    
    for i, metric1 in enumerate(metrics):
        for metric2 in metrics[i+1:]:  # Only upper triangle to avoid duplicates
            r, p_value = pearsonr(data[metric1], data[metric2])
            
            correlations.append({
                'Metric_1': metric1,
                'Metric_2': metric2,
                'Pearson_r': r,
                'p_value': p_value,
                'Significant': p_value < 0.05,
                'Interpretation': interpret_correlation(r)
            })
    
    return pd.DataFrame(correlations)

def interpret_correlation(r):
    """Interpret correlation strength"""
    abs_r = abs(r)
    if abs_r < 0.3:
        return "Weak"
    elif abs_r < 0.7:
        return "Moderate"
    else:
        return "Strong"

correlation_df = calculate_correlations(df)
print("\nPearson Correlation Analysis:")
print(correlation_df.to_string())

# Create correlation matrix visualization
plt.figure(figsize=(8, 6))
correlation_matrix = df[['TRR', 'PLR', 'NDI', 'JVI']].corr()
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, 
            square=True, linewidths=1, cbar_kws={"shrink": 0.8})
plt.title('Correlation Matrix: Derived Metrics')
plt.tight_layout()
plt.savefig('correlation_matrix.png', dpi=300, bbox_inches='tight')
plt.show()

def calculate_correlations(data):
    """Calculate Pearson correlation coefficients between all metric pairs"""
    metrics = ['TRR', 'PLR', 'NDI', 'JVI']  # Exclude ASI since it's derived from these
    
    correlations = []
    
    for i, metric1 in enumerate(metrics):
        for metric2 in metrics[i+1:]:  # Only upper triangle to avoid duplicates
            r, p_value = pearsonr(data[metric1], data[metric2])
            
            correlations.append({
                'Metric_1': metric1,
                'Metric_2': metric2,
                'Pearson_r': r,
                'p_value': p_value,
                'Significant': p_value < 0.05,
                'Interpretation': interpret_correlation(r)
            })
    
    return pd.DataFrame(correlations)

def interpret_correlation(r):
    """Interpret correlation strength"""
    abs_r = abs(r)
    if abs_r < 0.3:
        return "Weak"
    elif abs_r < 0.7:
        return "Moderate"
    else:
        return "Strong"

correlation_df = calculate_correlations(df)
print("\nPearson Correlation Analysis:")
print(correlation_df.to_string())

# Create correlation matrix visualization
plt.figure(figsize=(8, 6))
correlation_matrix = df[['TRR', 'PLR', 'NDI', 'JVI']].corr()
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, 
            square=True, linewidths=1, cbar_kws={"shrink": 0.8})
plt.title('Correlation Matrix: Derived Metrics')
plt.tight_layout()
plt.savefig('correlation_matrix.png', dpi=300, bbox_inches='tight')
plt.show()

def calculate_confidence_intervals(data, device, metric, confidence=0.95):
    """Calculate 95% confidence interval for mean"""
    device_data = data[data['Device'] == device][metric].values
    
    n = len(device_data)
    mean = np.mean(device_data)
    std_err = stats.sem(device_data)  # Standard error of mean
    
    # Calculate confidence interval
    ci = std_err * t_dist.ppf((1 + confidence) / 2, n - 1)
    
    return {
        'Device': device,
        'Metric': metric,
        'Mean': mean,
        'Std_Dev': np.std(device_data, ddof=1),
        'Std_Error': std_err,
        'CI_Lower': mean - ci,
        'CI_Upper': mean + ci,
        'CI_Width': 2 * ci
    }

# Calculate CIs for all metrics and devices
ci_results = []
for device in ['WIP', 'SHS']:
    for metric in metrics:
        ci_result = calculate_confidence_intervals(df, device, metric)
        ci_results.append(ci_result)

ci_df = pd.DataFrame(ci_results)
print("\n95% Confidence Intervals:")
print(ci_df.to_string())

def create_enhanced_table1(data):
    """Create enhanced version of Table 1 with confidence intervals"""
    
    summary_stats = []
    
    for device in ['WIP', 'SHS']:
        device_data = data[data['Device'] == device]
        
        for metric in metrics:
            values = device_data[metric].values
            n = len(values)
            mean = np.mean(values)
            std = np.std(values, ddof=1)
            se = stats.sem(values)
            ci = se * t_dist.ppf(0.975, n - 1)  # 95% CI
            
            summary_stats.append({
                'Device': device,
                'Metric': metric,
                'Mean': f"{mean:.2f}",
                'SD': f"{std:.2f}",
                '95% CI': f"[{mean-ci:.2f}, {mean+ci:.2f}]",
                'Median': f"{np.median(values):.2f}",
                'Min': f"{np.min(values):.2f}",
                'Max': f"{np.max(values):.2f}"
            })
    
    return pd.DataFrame(summary_stats)

enhanced_table = create_enhanced_table1(df)
print("\nEnhanced Summary Statistics (for supplementary material):")
print(enhanced_table.to_string())

# Export to Excel
enhanced_table.to_excel('enhanced_table1_with_CI.xlsx', index=False)

# Create box plots comparing WIP vs SHS
fig, axes = plt.subplots(2, 3, figsize=(15, 10))
axes = axes.flatten()

for idx, metric in enumerate(metrics):
    ax = axes[idx]
    
    # Prepare data for boxplot
    wip_data = df[df['Device'] == 'WIP'][metric]
    shs_data = df[df['Device'] == 'SHS'][metric]
    
    # Create boxplot
    bp = ax.boxplot([wip_data, shs_data], labels=['WIP', 'SHS'],
                     patch_artist=True, showmeans=True)
    
    # Color the boxes
    bp['boxes'][0].set_facecolor('lightblue')
    bp['boxes'][1].set_facecolor('lightcoral')
    
    # Add title and labels
    ax.set_ylabel(f'{metric} (%)')
    ax.set_title(f'{metric} Distribution')
    ax.grid(True, alpha=0.3)
    
    # Add statistical significance annotation
    comparison = comparison_df[comparison_df['Metric'] == metric].iloc[0]
    if comparison['Significant']:
        ax.text(0.5, 0.95, f"p = {comparison['p_value']:.4f}*", 
               transform=ax.transAxes, ha='center', va='top',
               bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.3))

# Remove empty subplot
axes[-1].remove()

plt.tight_layout()
plt.savefig('wip_vs_shs_comparison.png', dpi=300, bbox_inches='tight')
plt.show()

def generate_results_text(comparison_df, correlation_df):
    """Generate formatted text for inclusion in thesis"""
    
    text = "### Statistical Validation of Device Comparisons\n\n"
    
    # Comparative tests
    text += "Mann-Whitney U tests (or independent t-tests where normality assumptions were met) "
    text += "were performed to compare WIP and SHS performance across all derived metrics. "
    
    significant_diffs = comparison_df[comparison_df['Significant']]
    if len(significant_diffs) > 0:
        text += f"Significant differences (p < 0.05) were observed for {len(significant_diffs)} "
        text += f"of {len(comparison_df)} metrics: "
        text += ", ".join([f"{row['Metric']} (p = {row['p_value']:.4f})" 
                          for _, row in significant_diffs.iterrows()])
        text += ". "
    else:
        text += "No statistically significant differences were observed between devices "
        text += "at the p < 0.05 level. "
    
    text += "\n\n"
    
    # Correlations
    text += "Pearson correlation analysis revealed interdependencies between metrics. "
    strong_corr = correlation_df[correlation_df['Interpretation'] == 'Strong']
    
    if len(strong_corr) > 0:
        text += "Strong correlations (|r| > 0.7) were found between: "
        for _, row in strong_corr.iterrows():
            text += f"{row['Metric_1']}-{row['Metric_2']} "
            text += f"(r = {row['Pearson_r']:.3f}, p = {row['p_value']:.4f}); "
        text += "confirming expected metric dependencies under attack conditions."
    
    return text

results_text = generate_results_text(comparison_df, correlation_df)
print("\n" + "="*80)
print("FORMATTED TEXT FOR THESIS:")
print("="*80)
print(results_text)

# Save to file
with open('statistical_results_text.txt', 'w') as f:
    f.write(results_text)
    
    
