import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
import json
import os
from datetime import datetime

warnings.filterwarnings('ignore')
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

os.makedirs('data/processed', exist_ok=True)

print("="*80)
print("INTELLIGENT IDS - DATA EXPLORATION")
print("="*80)
print(f"Analysis started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)

print("\n[1/10] Loading dataset...")

import os
current_dir = os.getcwd()
print(f"Current directory: {current_dir}")

if 'notebooks' in current_dir:
    data_path = '../data/raw/CICIDS2017.csv'
else:
    data_path = 'data/raw/CICIDS2017.csv'

print(f"Loading from: {data_path}")
df = pd.read_csv(data_path)

df.columns = df.columns.str.strip()

print("\n" + "="*80)
print("DATASET LOADED SUCCESSFULLY")
print("="*80)
print(f"Number of rows: {df.shape[0]:,}")
print(f"Number of columns: {df.shape[1]}")
print(f"Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
print("="*80)

print("\n[2/10] Displaying first 5 rows...")
print("\nFirst 5 rows of the dataset:")
print(df.head().to_string())

print("\n[3/10] Analyzing column information...")
print("\nColumn Names (Total: {}):".format(len(df.columns)))
print("="*80)
for i, col in enumerate(df.columns, 1):
    dtype = df[col].dtype
    print(f"{i:2d}. {col:<40} | Type: {dtype}")

print("\nData Types Summary:")
print(df.dtypes.value_counts())
print(f"\nNumeric columns: {len(df.select_dtypes(include=[np.number]).columns)}")
print(f"Object columns: {len(df.select_dtypes(include=['object']).columns)}")

print("\n[4/10] Checking data quality...")
print("\nChecking for missing values...")
missing = df.isnull().sum()
missing_pct = (missing / len(df)) * 100

missing_df = pd.DataFrame({
    'Column': df.columns,
    'Missing_Count': missing.values,
    'Percentage': missing_pct.values
})

missing_df = missing_df[missing_df['Missing_Count'] > 0].sort_values('Percentage', ascending=False)

if len(missing_df) > 0:
    print(f"\nFound {len(missing_df)} columns with missing values:")
    print(missing_df.to_string(index=False))
else:
    print("\nNo missing values found!")

print("\nChecking for infinite values...")
numeric_cols = df.select_dtypes(include=[np.number]).columns
inf_counts = {}

for col in numeric_cols:
    inf_count = np.isinf(df[col]).sum()
    if inf_count > 0:
        inf_counts[col] = inf_count

if inf_counts:
    print(f"\nFound {len(inf_counts)} columns with infinite values:")
    inf_df = pd.DataFrame(list(inf_counts.items()), columns=['Column', 'Inf_Count'])
    inf_df['Percentage'] = (inf_df['Inf_Count'] / len(df)) * 100
    inf_df = inf_df.sort_values('Inf_Count', ascending=False)
    print(inf_df.to_string(index=False))
else:
    print("\nNo infinite values found!")

print("\nChecking for duplicate rows...")
duplicates = df.duplicated().sum()
print(f"Number of duplicate rows: {duplicates:,}")
print(f"Percentage: {(duplicates/len(df)*100):.2f}%")

print("\n[5/10] Analyzing attack type distribution...")

label_column = None
possible_label_columns = ['Label', 'label', 'class', 'Class', 'Attack', 'attack']
for col in possible_label_columns:
    if col in df.columns:
        label_column = col
        break

if label_column is None:
    print("\nSearching for label column in dataset...")
    for col in df.columns:
        if 'label' in col.lower() or 'class' in col.lower() or 'attack' in col.lower():
            label_column = col
            break

if label_column is None:
    print("\nERROR: Could not find label column!")
    print("Available columns:")
    for i, col in enumerate(df.columns, 1):
        print(f"{i:2d}. '{col}'")
    print("\nPlease check your dataset. The last column should contain attack labels.")
    exit(1)

print(f"\nUsing label column: '{label_column}'")

print("\n" + "="*80)
print("ATTACK TYPE DISTRIBUTION")
print("="*80)

label_counts = df[label_column].value_counts()
label_pct = (label_counts / len(df)) * 100

attack_df = pd.DataFrame({
    'Attack_Type': label_counts.index,
    'Count': label_counts.values,
    'Percentage': label_pct.values
})

print("\n" + attack_df.to_string(index=False))
print("\n" + "="*80)
print(f"Total unique attack types: {df[label_column].nunique()}")
print("="*80)

if df[label_column].nunique() == 1 and 'BENIGN' in df[label_column].values:
    print("\n" + "!"*80)
    print("WARNING: Dataset contains ONLY benign traffic!")
    print("!"*80)
    print("This file appears to be only benign samples from CICIDS2017.")
    print("You need to load the complete dataset with attack samples.")
    print("\nCICIDS2017 typically has multiple CSV files for different days:")
    print("- Monday-WorkingHours.pcap_ISCX.csv (Benign)")
    print("- Tuesday-WorkingHours.pcap_ISCX.csv (Brute Force, FTP, SSH)")
    print("- Wednesday-workingHours.pcap_ISCX.csv (DoS, Heartbleed)")
    print("- Thursday-WorkingHours.pcap_ISCX.csv (Web Attack, Infiltration)")
    print("- Friday-WorkingHours.pcap_ISCX.csv (DDoS, PortScan, Botnet)")
    print("\nPlease combine all CSV files or use a file with mixed traffic.")
    print("!"*80)

print("\n[6/10] Creating attack distribution visualization...")
plt.figure(figsize=(14, 8))
label_counts.plot(kind='bar', color='steelblue', edgecolor='black')
plt.title('Distribution of Attack Types', fontsize=18, fontweight='bold', pad=20)
plt.xlabel('Attack Type', fontsize=14, fontweight='bold')
plt.ylabel('Number of Samples', fontsize=14, fontweight='bold')
plt.xticks(rotation=45, ha='right', fontsize=11)
plt.yticks(fontsize=11)
plt.grid(axis='y', alpha=0.3, linestyle='--')
plt.tight_layout()
plt.savefig('data/processed/attack_distribution.png', dpi=300, bbox_inches='tight')
plt.close()
print("Chart saved: data/processed/attack_distribution.png")

print("\n[7/10] Analyzing benign vs attack traffic...")
benign_count = (df[label_column].str.upper() == 'BENIGN').sum()
attack_count = (df[label_column].str.upper() != 'BENIGN').sum()

print("\n" + "="*80)
print("BENIGN VS ATTACK TRAFFIC")
print("="*80)
print(f"Benign traffic: {benign_count:,} ({benign_count/len(df)*100:.2f}%)")
print(f"Attack traffic: {attack_count:,} ({attack_count/len(df)*100:.2f}%)")
print("="*80)

if attack_count > 0:
    plt.figure(figsize=(10, 8))
    colors = ['#90EE90', '#FF6B6B']
    explode = (0.05, 0)
    plt.pie([benign_count, attack_count], 
            labels=['Benign', 'Attack'],
            autopct='%1.1f%%',
            colors=colors,
            explode=explode,
            shadow=True,
            startangle=90,
            textprops={'fontsize': 14, 'fontweight': 'bold'})
    plt.title('Benign vs Attack Traffic Distribution', fontsize=18, fontweight='bold', pad=20)
    plt.savefig('data/processed/benign_vs_attack.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Chart saved: data/processed/benign_vs_attack.png")
else:
    print("Skipping benign vs attack chart (no attacks in dataset)")

print("\n[8/10] Analyzing key features...")
important_features = [
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Backward Packets',
    'Flow Bytes/s', 
    'Flow Packets/s',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean'
]

available_features = [f for f in important_features if f in df.columns]

if available_features:
    print(f"\nAnalyzing {len(available_features)} key features...")
    print("\nStatistical Summary:")
    print(df[available_features].describe().to_string())
    
    print("\nCreating feature distribution plots...")
    num_features = min(len(available_features), 9)
    rows = (num_features + 2) // 3
    cols = min(num_features, 3)
    
    fig, axes = plt.subplots(rows, cols, figsize=(18, rows*5))
    axes = axes.ravel() if num_features > 1 else [axes]
    
    for idx, feature in enumerate(available_features[:num_features]):
        data = df[feature].replace([np.inf, -np.inf], np.nan).dropna()
        axes[idx].hist(data, bins=50, edgecolor='black', color='skyblue', alpha=0.7)
        axes[idx].set_title(feature, fontsize=12, fontweight='bold')
        axes[idx].set_xlabel('Value', fontsize=10)
        axes[idx].set_ylabel('Frequency', fontsize=10)
        axes[idx].grid(axis='y', alpha=0.3)
    
    for idx in range(num_features, len(axes)):
        axes[idx].set_visible(False)
    
    plt.tight_layout()
    plt.savefig('data/processed/feature_distributions.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Chart saved: data/processed/feature_distributions.png")
else:
    print("\nNo matching features found for analysis")

print("\n[9/10] Calculating feature correlations...")
numeric_df = df.select_dtypes(include=[np.number])

if len(numeric_df.columns) > 1:
    print(f"Analyzing correlations for {len(numeric_df.columns)} numeric features...")
    
    sample_size = min(10000, len(numeric_df))
    print(f"Using sample of {sample_size:,} rows for correlation calculation...")
    
    sampled_df = numeric_df.sample(sample_size, random_state=42)
    sampled_df = sampled_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    correlation_matrix = sampled_df.corr()
    
    plt.figure(figsize=(24, 20))
    sns.heatmap(correlation_matrix, 
                cmap='coolwarm', 
                center=0,
                square=True,
                linewidths=0.5,
                cbar_kws={"shrink": 0.8},
                xticklabels=True,
                yticklabels=True)
    plt.title('Feature Correlation Heatmap', fontsize=20, fontweight='bold', pad=20)
    plt.xticks(rotation=45, ha='right', fontsize=8)
    plt.yticks(rotation=0, fontsize=8)
    plt.tight_layout()
    plt.savefig('data/processed/correlation_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Chart saved: data/processed/correlation_matrix.png")
    
    print("\nTop 15 highest correlations:")
    corr_pairs = correlation_matrix.unstack()
    corr_pairs = corr_pairs[corr_pairs < 1]
    top_corr = corr_pairs.abs().sort_values(ascending=False).head(15)
    
    for idx, (features, corr_value) in enumerate(top_corr.items(), 1):
        print(f"{idx:2d}. {features[0]:<35} <--> {features[1]:<35} : {corr_value:.4f}")
else:
    print("Not enough numeric columns for correlation analysis")

print("\n[10/10] Generating exploration summary...")

summary = {
    'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'total_samples': int(df.shape[0]),
    'total_features': int(df.shape[1]),
    'numeric_features': int(len(numeric_cols)),
    'object_features': int(len(df.select_dtypes(include=['object']).columns)),
    'attack_types': int(df[label_column].nunique()),
    'attack_list': df[label_column].unique().tolist(),
    'missing_values': int(df.isnull().sum().sum()),
    'infinite_values': int(sum(inf_counts.values())) if inf_counts else 0,
    'duplicate_rows': int(duplicates),
    'benign_count': int(benign_count),
    'attack_count': int(attack_count),
    'benign_percentage': float(benign_count/len(df)*100),
    'attack_percentage': float(attack_count/len(df)*100),
    'memory_usage_mb': float(df.memory_usage(deep=True).sum() / 1024**2)
}

with open('data/processed/exploration_summary.json', 'w') as f:
    json.dump(summary, f, indent=4)

print("\n" + "="*80)
print("DATA EXPLORATION SUMMARY")
print("="*80)
print(f"Analysis Date:        {summary['analysis_date']}")
print(f"Total Samples:        {summary['total_samples']:,}")
print(f"Total Features:       {summary['total_features']}")
print(f"  - Numeric:          {summary['numeric_features']}")
print(f"  - Object:           {summary['object_features']}")
print(f"Attack Types:         {summary['attack_types']}")
print(f"Data Quality:")
print(f"  - Missing Values:   {summary['missing_values']:,}")
print(f"  - Infinite Values:  {summary['infinite_values']:,}")
print(f"  - Duplicate Rows:   {summary['duplicate_rows']:,}")
print(f"Traffic Distribution:")
print(f"  - Benign:           {summary['benign_count']:,} ({summary['benign_percentage']:.2f}%)")
print(f"  - Attack:           {summary['attack_count']:,} ({summary['attack_percentage']:.2f}%)")
print(f"Memory Usage:         {summary['memory_usage_mb']:.2f} MB")
print("="*80)

print("\nAttack Types Found:")
for i, attack_type in enumerate(summary['attack_list'], 1):
    count = label_counts[attack_type]
    pct = (count / len(df)) * 100
    print(f"  {i:2d}. {attack_type:<30} : {count:>10,} ({pct:>6.2f}%)")

print("\n" + "="*80)
print("FILES GENERATED")
print("="*80)
print("1. data/processed/exploration_summary.json")
print("2. data/processed/attack_distribution.png")
if attack_count > 0:
    print("3. data/processed/benign_vs_attack.png")
print("4. data/processed/feature_distributions.png")
print("5. data/processed/correlation_matrix.png")
print("="*80)

print("\n" + "="*80)
print("DATA EXPLORATION COMPLETE!")
print("="*80)
if attack_count == 0:
    print("\n" + "!"*80)
    print("IMPORTANT: Your dataset contains ONLY benign traffic!")
    print("You need a dataset with both benign and attack samples for training.")
    print("Please load the complete CICIDS2017 dataset or combine multiple CSV files.")
    print("!"*80)
else:
    print("Next Steps:")
    print("1. Review the generated visualizations in data/processed/")
    print("2. Check exploration_summary.json for detailed statistics")
    print("3. Proceed to data preprocessing: cd backend/app && python test_preprocessing.py")
print("="*80)
print(f"\nAnalysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)