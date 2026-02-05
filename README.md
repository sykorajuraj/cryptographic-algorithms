# Cryptographic Algorithms

Experimental study aims in understanding, comparing, and examining cryptographic algorithms (symmetric, asymmetric encryption, and hash functions) for the course of **Software Development M** at the University of Bologna. Includes experimental implementation of **AES-128/**, **RSA**, and **Perfect Hash Functions** in C/C++.

## Project Overview

This project implements three fundamental cryptographic primitives from scratch:
- **AES-128**: Symmetric encryption with ECB, CBC, and CTR modes
- **RSA**: Asymmetric encryption with 512-4096 bit keys and CRT optimization
- **Perfect Hash Functions**: CHD and BDZ algorithms for collision-free hashing

## Quick Start

```bash
# Clone the repository
git clone https://github.com/sykorajuraj/cryptographic-algorithms
cd cryptographic-algorithms

# Build everything
mkdir build && cd build
cmake ..
make

# Build everything, run benchmarks, and run all tests
make run-all

# Run tests with detailed performance output
ctest --verbose

# Run tests manually
./test_aes
./test_rsa
./test_phf

# Run AES benchmarks
make run-benchmarks
```

## Project Structure

```
src/          # Implementation files (aes.c, rsa.c, hash functions)
tests/        # Unit tests validating correctness and performance
benchmarks/   # Performance measurements of AES
examples/     # Usage example of AES
docs/         # Full experimental study documentation (report)
```

## Documentation

See `docs/JurajSykora_ExperimentalStudy_AES_RSA_PHF.pdf` for detailed implementation analysis, performance results, and comparative study.

**License MIT - Juraj Sýkora**