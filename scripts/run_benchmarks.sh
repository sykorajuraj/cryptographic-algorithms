#!/bin/bash
# scripts/run_benchmarks.sh
# Script to run all benchmarks and collect results
# Author: Juraj Sýkora

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║         Cryptographic Algorithms Benchmark Suite        ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create results directory
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

# Build benchmarks
echo -e "${YELLOW}Building benchmarks...${NC}"
make benchmarks

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build successful!${NC}\n"

# System information
echo -e "${CYAN}System Information:${NC}"
echo "  OS      : $(uname -s)"
echo "  Kernel  : $(uname -r)"
echo "  CPU     : $(grep -m 1 'model name' /proc/cpuinfo | cut -d':' -f2 | xargs || echo 'N/A')"
echo "  Cores   : $(nproc || echo 'N/A')"
echo "  Date    : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Run each benchmark
BENCH_DIR="bin"
if [ ! -d "$BENCH_DIR" ]; then
    echo -e "${RED}✗ Benchmark directory not found!${NC}"
    exit 1
fi

for bench in "$BENCH_DIR"/bench_*; do
    if [ -x "$bench" ]; then
        bench_name=$(basename "$bench")
        echo -e "${CYAN}═══════════════════════════════════════════${NC}"
        echo -e "${CYAN}Running: ${bench_name}${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════${NC}\n"
        
        # Run benchmark and capture output
        output_file="$RESULTS_DIR/${bench_name}_$(date +%Y%m%d_%H%M%S).log"
        
        if ./"$bench" | tee "$output_file"; then
            echo -e "\n${GREEN}✓ ${bench_name} completed${NC}"
            echo -e "${GREEN}  Output saved to: ${output_file}${NC}\n"
        else
            echo -e "\n${RED}✗ ${bench_name} failed${NC}\n"
        fi
    fi
done

# Summary
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    Benchmark Summary                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ -f "$RESULTS_DIR/benchmarks.csv" ]; then
    echo -e "${GREEN}✓ Results saved to: ${RESULTS_DIR}/benchmarks.csv${NC}"
    echo -e "${YELLOW}  You can plot results using: python3 scripts/plot_results.py${NC}"
else
    echo -e "${YELLOW}⚠ No CSV results file generated${NC}"
fi

echo -e "\n${GREEN}✓ All benchmarks completed!${NC}\n"

# Optional: Show summary statistics
if [ -f "$RESULTS_DIR/benchmarks.csv" ]; then
    echo -e "${CYAN}Quick Summary:${NC}"
    echo "  Total entries: $(tail -n +2 "$RESULTS_DIR/benchmarks.csv" | wc -l)"
    echo "  Results location: $RESULTS_DIR/"
    echo ""
fi

exit 0