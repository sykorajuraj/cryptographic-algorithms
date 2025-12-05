#!/usr/bin/env python3
"""
scripts/plot_results.py
Plot benchmark results from CSV file
Author: Juraj Sýkora <juraj.sykora@studio.unibo.it>
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10

def load_results(csv_file):
    """Load benchmark results from CSV file"""
    try:
        df = pd.read_csv(csv_file)
        print(f"✓ Loaded {len(df)} benchmark results from {csv_file}")
        return df
    except FileNotFoundError:
        print(f"✗ Error: File {csv_file} not found!")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error loading CSV: {e}")
        sys.exit(1)

def plot_throughput_by_mode(df, output_dir):
    """Plot throughput comparison by mode"""
    plt.figure(figsize=(14, 8))
    
    # Filter and prepare data
    encrypt_data = df[df['Operation'] == 'Encrypt'].copy()
    
    if len(encrypt_data) == 0:
        print("⚠ No encryption data to plot")
        return
    
    # Create grouped bar chart
    modes = encrypt_data['Mode'].unique()
    x = range(len(encrypt_data))
    
    plt.bar(x, encrypt_data['Throughput_MBps'], 
            color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'])
    
    plt.xlabel('Benchmark Configuration', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontsize=12, fontweight='bold')
    plt.title('AES-128 Throughput by Mode and Data Size', 
              fontsize=14, fontweight='bold', pad=20)
    
    # Set x-axis labels
    labels = [f"{row['Mode']}\n{row['DataSize']}B" 
              for _, row in encrypt_data.iterrows()]
    plt.xticks(x, labels, rotation=45, ha='right')
    
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    output_file = os.path.join(output_dir, 'throughput_comparison.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_encrypt_vs_decrypt(df, output_dir):
    """Plot encryption vs decryption comparison"""
    plt.figure(figsize=(12, 8))
    
    # Prepare data
    encrypt = df[df['Operation'] == 'Encrypt']
    decrypt = df[df['Operation'] == 'Decrypt']
    
    if len(encrypt) == 0 or len(decrypt) == 0:
        print("⚠ Missing encryption or decryption data")
        return
    
    # Merge on common keys
    merged = pd.merge(encrypt, decrypt, 
                     on=['Algorithm', 'Mode', 'DataSize'],
                     suffixes=('_enc', '_dec'))
    
    x = range(len(merged))
    width = 0.35
    
    plt.bar([i - width/2 for i in x], merged['Throughput_MBps_enc'], 
            width, label='Encryption', color='#3498db')
    plt.bar([i + width/2 for i in x], merged['Throughput_MBps_dec'], 
            width, label='Decryption', color='#e74c3c')
    
    plt.xlabel('Configuration', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontsize=12, fontweight='bold')
    plt.title('AES-128: Encryption vs Decryption Performance', 
              fontsize=14, fontweight='bold', pad=20)
    
    labels = [f"{row['Mode']}\n{row['DataSize']}B" 
              for _, row in merged.iterrows()]
    plt.xticks(x, labels, rotation=45, ha='right')
    
    plt.legend(fontsize=11, loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    output_file = os.path.join(output_dir, 'encrypt_vs_decrypt.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_throughput_by_size(df, output_dir):
    """Plot throughput scaling with data size"""
    plt.figure(figsize=(12, 8))
    
    encrypt_data = df[df['Operation'] == 'Encrypt'].copy()
    
    if len(encrypt_data) == 0:
        print("⚠ No encryption data to plot")
        return
    
    # Plot each mode separately
    modes = encrypt_data['Mode'].unique()
    colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6']
    
    for i, mode in enumerate(modes):
        mode_data = encrypt_data[encrypt_data['Mode'] == mode].sort_values('DataSize')
        plt.plot(mode_data['DataSize'], mode_data['Throughput_MBps'], 
                marker='o', linewidth=2, markersize=8,
                label=mode, color=colors[i % len(colors)])
    
    plt.xlabel('Data Size (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontsize=12, fontweight='bold')
    plt.title('AES-128: Throughput Scaling with Data Size', 
              fontsize=14, fontweight='bold', pad=20)
    
    plt.xscale('log')
    plt.legend(fontsize=11, loc='best')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    output_file = os.path.join(output_dir, 'throughput_scaling.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_time_distribution(df, output_dir):
    """Plot execution time distribution"""
    plt.figure(figsize=(12, 8))
    
    modes = df['Mode'].unique()
    colors = ['#3498db', '#2ecc71', '#e74c3c']
    
    for i, mode in enumerate(modes):
        mode_data = df[df['Mode'] == mode]
        plt.scatter(mode_data['DataSize'], mode_data['Time_us'], 
                   label=mode, alpha=0.6, s=100, color=colors[i % len(colors)])
    
    plt.xlabel('Data Size (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Execution Time (μs)', fontsize=12, fontweight='bold')
    plt.title('AES-128: Execution Time by Mode and Size', 
              fontsize=14, fontweight='bold', pad=20)
    
    plt.xscale('log')
    plt.yscale('log')
    plt.legend(fontsize=11, loc='best')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    output_file = os.path.join(output_dir, 'time_distribution.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def generate_summary_stats(df, output_dir):
    """Generate and save summary statistics"""
    print("\n" + "="*60)
    print("BENCHMARK SUMMARY STATISTICS")
    print("="*60)
    
    # Overall statistics
    print("\nOverall Statistics:")
    print(f"  Total benchmarks run: {len(df)}")
    print(f"  Algorithms tested  : {', '.join(df['Algorithm'].unique())}")
    print(f"  Modes tested       : {', '.join(df['Mode'].unique())}")
    
    # Performance statistics
    print("\nPerformance Metrics:")
    print(f"  Max throughput     : {df['Throughput_MBps'].max():.2f} MB/s")
    print(f"  Min throughput     : {df['Throughput_MBps'].min():.2f} MB/s")
    print(f"  Mean throughput    : {df['Throughput_MBps'].mean():.2f} MB/s")
    print(f"  Median throughput  : {df['Throughput_MBps'].median():.2f} MB/s")
    
    # By mode
    print("\nPerformance by Mode:")
    for mode in df['Mode'].unique():
        mode_data = df[df['Mode'] == mode]
        avg_throughput = mode_data['Throughput_MBps'].mean()
        print(f"  {mode:8s} - Avg: {avg_throughput:6.2f} MB/s")
    
    # Save to file
    summary_file = os.path.join(output_dir, 'summary_stats.txt')
    with open(summary_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("AES-128 BENCHMARK SUMMARY\n")
        f.write("="*60 + "\n\n")
        
        f.write("Overall Statistics:\n")
        f.write(f"  Total benchmarks: {len(df)}\n")
        f.write(f"  Max throughput: {df['Throughput_MBps'].max():.2f} MB/s\n")
        f.write(f"  Mean throughput: {df['Throughput_MBps'].mean():.2f} MB/s\n\n")
        
        f.write("Performance by Mode:\n")
        for mode in df['Mode'].unique():
            mode_data = df[df['Mode'] == mode]
            f.write(f"  {mode}: {mode_data['Throughput_MBps'].mean():.2f} MB/s\n")
    
    print(f"\n✓ Summary saved to: {summary_file}")
    print("="*60 + "\n")

def main():
    """Main function"""
    # Configuration
    csv_file = 'results/benchmarks.csv'
    output_dir = 'results'
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                                                          ║")
    print("║          Benchmark Results Visualization Tool           ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    
    # Load data
    df = load_results(csv_file)
    
    # Display data info
    print(f"\nDataset Info:")
    print(f"  Shape: {df.shape}")
    print(f"  Columns: {', '.join(df.columns)}")
    print()
    
    # Generate plots
    print("Generating plots...")
    plot_throughput_by_mode(df, output_dir)
    plot_encrypt_vs_decrypt(df, output_dir)
    plot_throughput_by_size(df, output_dir)
    plot_time_distribution(df, output_dir)
    
    # Generate summary statistics
    generate_summary_stats(df, output_dir)
    
    print("\n✅ All visualizations complete!")
    print(f"Results saved to: {output_dir}/\n")

if __name__ == '__main__':
    main()