import os
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
from scipy import stats
from scipy.stats import mannwhitneyu, pearsonr
import seaborn as sns
import matplotlib.pyplot as plt

# ==========================================================
# PATHS
# ==========================================================

BASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUTPUT_DIR = os.path.join(BASE_PATH, "results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE_DIRECTORIES = {
    'mitm': {
        'mitm_wip': 'WIP',
        'mitm_shs': 'SHS'
    },
    'normal': {
        'normal_wip': 'WIP',
        'normal_shs': 'SHS'
    }
}

# ==========================================================
# SAFE FLOAT PARSER
# ==========================================================

def safe_float(value):
    try:
        return float(str(value)
                     .replace('+', '')
                     .replace('s', '')
                     .replace('n', '')
                     .strip())
    except:
        return 0.0

# ==========================================================
# XML PARSER
# ==========================================================

def parse_flowmonitor_xml(filepath, device, scenario):

    tree = ET.parse(filepath)
    root = tree.getroot()

    rows = []

    for flow in root.iter('Flow'):

        try:
            tx_packets = int(flow.attrib.get('txPackets', 0))
            rx_packets = int(flow.attrib.get('rxPackets', 0))
            lost_packets = int(flow.attrib.get('lostPackets', 0))

            delay_sum = safe_float(flow.attrib.get('delaySum', '0'))
            jitter_sum = safe_float(flow.attrib.get('jitterSum', '0'))

            tx_bytes = int(flow.attrib.get('txBytes', 0))
            rx_bytes = int(flow.attrib.get('rxBytes', 0))

            # Metrics
            trr = (rx_packets / tx_packets) * 100 if tx_packets else 0
            plr = (lost_packets / tx_packets) * 100 if tx_packets else 0
            avg_delay = delay_sum / rx_packets if rx_packets else 0
            avg_jitter = jitter_sum / rx_packets if rx_packets else 0

            ndi = trr
            jvi = 100 / (1 + avg_jitter * 1000)

            asi = (
                (trr * 0.4) +
                ((100 - plr) * 0.3) +
                ((1 / (1 + avg_delay)) * 15) +
                ((1 / (1 + avg_jitter)) * 15)
            )

            rows.append({
                'Scenario': scenario,
                'Device': device,
                'TX_Packets': tx_packets,
                'RX_Packets': rx_packets,
                'Lost_Packets': lost_packets,
                'TX_Bytes': tx_bytes,
                'RX_Bytes': rx_bytes,
                'Delay': avg_delay,
                'Jitter': avg_jitter,
                'TRR': trr,
                'PLR': plr,
                'NDI': ndi,
                'JVI': jvi,
                'ASI': asi,
                'Source_File': os.path.basename(filepath)
            })

        except Exception as e:
            print(f"Error in {filepath}: {e}")

    return rows

# ==========================================================
# LOAD DATA
# ==========================================================

print("=" * 70)
print("LOADING FLOWMONITOR XML FILES")
print("=" * 70)

print("BASE_PATH:", BASE_PATH)

all_rows = []

for scenario, folders in BASE_DIRECTORIES.items():

    scenario_path = os.path.join(BASE_PATH, scenario)

    if not os.path.isdir(scenario_path):
        print(f"Missing: {scenario_path}")
        continue

    available = {
        f.lower(): f for f in os.listdir(scenario_path)
        if os.path.isdir(os.path.join(scenario_path, f))
    }

    for folder_name, device in folders.items():

        folder_key = folder_name.lower()

        if folder_key not in available:
            print(f"Missing folder: {folder_name}")
            continue

        folder_path = os.path.join(scenario_path, available[folder_key])

        print(f"Reading: {folder_path}")

        for file in os.listdir(folder_path):

            if file.lower().endswith(".xml"):

                path = os.path.join(folder_path, file)

                all_rows.extend(parse_flowmonitor_xml(path, device, scenario))

# ==========================================================
# DATAFRAME
# ==========================================================

df = pd.DataFrame(all_rows)

print("\nDATA SUMMARY")
print(df.head())
print("Total:", len(df))

if df.empty:
    raise SystemExit("No data loaded.")

df.to_csv(os.path.join(OUTPUT_DIR, "flowmonitor_dataset.csv"), index=False)

# ==========================================================
# METRICS
# ==========================================================

metrics = ['TRR', 'PLR', 'NDI', 'JVI', 'ASI']

# ==========================================================
# NORMALITY
# ==========================================================

def test_normality(data, device, metric):

    vals = data[data['Device'] == device][metric]

    if len(vals) < 3:
        return False, np.nan

    _, p = stats.shapiro(vals)
    return p > 0.05, p

normality = []

for m in metrics:
    wip_n, wip_p = test_normality(df, 'WIP', m)
    shs_n, shs_p = test_normality(df, 'SHS', m)

    normality.append({
        'Metric': m,
        'WIP_Normal': wip_n,
        'SHS_Normal': shs_n,
        'WIP_p': wip_p,
        'SHS_p': shs_p
    })

normality_df = pd.DataFrame(normality)

# ==========================================================
# DEVICE COMPARISON
# ==========================================================

def compare_devices(data, metric):

    wip = data[data['Device'] == 'WIP'][metric]
    shs = data[data['Device'] == 'SHS'][metric]

    if len(wip) < 2 or len(shs) < 2:
        return None

    if stats.shapiro(wip)[1] > 0.05 and stats.shapiro(shs)[1] > 0.05:
        stat, p = stats.ttest_ind(wip, shs)
        test = "t-test"
    else:
        stat, p = mannwhitneyu(wip, shs)
        test = "Mann-Whitney"

    return {
        'Metric': metric,
        'WIP_Mean': wip.mean(),
        'SHS_Mean': shs.mean(),
        'p_value': p,
        'Test': test,
        'Significant': p < 0.05
    }

comparison_df = pd.DataFrame(
    [r for r in (compare_devices(df, m) for m in metrics) if r]
)

# ==========================================================
# SCENARIO COMPARISON
# ==========================================================

def compare_scenarios(data, metric):

    normal = data[data['Scenario'] == 'normal'][metric]
    mitm = data[data['Scenario'] == 'mitm'][metric]

    if len(normal) == 0 or len(mitm) == 0:
        return None

    _, p = mannwhitneyu(normal, mitm)

    return {
        'Metric': metric,
        'NORMAL_Mean': normal.mean(),
        'MITM_Mean': mitm.mean(),
        'p_value': p,
        'Significant': p < 0.05
    }

scenario_df = pd.DataFrame(
    [r for r in (compare_scenarios(df, m) for m in metrics) if r]
)

# ==========================================================
# CORRELATION (SAFE)
# ==========================================================

def safe_pearson(x, y):
    if len(x) < 2 or len(y) < 2:
        return np.nan, np.nan
    if np.std(x) == 0 or np.std(y) == 0:
        return np.nan, np.nan
    return pearsonr(x, y)

corr_metrics = ['TRR', 'PLR', 'NDI', 'JVI']

corr = []

for i, m1 in enumerate(corr_metrics):
    for m2 in corr_metrics[i+1:]:
        r, p = safe_pearson(df[m1], df[m2])
        corr.append({'M1': m1, 'M2': m2, 'r': r, 'p': p})

corr_df = pd.DataFrame(corr)

# ==========================================================
# PLOTS
# ==========================================================

plt.figure(figsize=(8, 6))
sns.heatmap(df[corr_metrics].corr(), annot=True, cmap='coolwarm')
plt.title("Correlation Matrix")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "correlation_matrix.png"), dpi=300)
plt.close()

fig, axes = plt.subplots(2, 3, figsize=(15, 10))
axes = axes.flatten()

for i, m in enumerate(metrics):
    sns.boxplot(data=df, x='Device', y=m, hue='Scenario', ax=axes[i])
    axes[i].set_title(m)

axes[-1].remove()

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "device_scenario.png"), dpi=300)
plt.close()

# ==========================================================
# EXPORT
# ==========================================================

comparison_df.to_excel(os.path.join(OUTPUT_DIR, "device_comparison.xlsx"), index=False)
scenario_df.to_excel(os.path.join(OUTPUT_DIR, "scenario_comparison.xlsx"), index=False)
corr_df.to_excel(os.path.join(OUTPUT_DIR, "correlation.xlsx"), index=False)

print("\nANALYSIS COMPLETE")
print("Outputs saved in:", OUTPUT_DIR)
