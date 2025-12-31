# cryptographic-algorithms
Experimental study aims in understanding, comparing and implementing of cryptographic algorithms (symmetric, asymmetric encryption, and hash functions) for course of Software Development at University of Bologna

```text
cryptographic-algorithms/
├── README.md
├── Makefile
├── LICENSE
│
├── docs/
│   ├── study.pdf              # Project documentation
│   └── slides.pdf             # Presentation slides
│
├── src/
│   ├── symmetric/
│   │   ├── aes.h             # AES-128 header
│   │   └── aes.c             # AES-128 implementation
│   │
│   ├── asymmetric/
│   │   ├── rsa.h             # RSA header (planned)
│   │   └── rsa.c             # RSA implementation (planned)
│   │
│   └── hash/
│       ├── sha256.h          # SHA-256 (planned)
│       ├── sha256.c
│       ├── chd.h             # CHD perfect hash (planned)
│       ├── chd.c
│       ├── bdz.h             # BDZ perfect hash (planned)
│       └── bdz.c
│
├── tests/
│   ├── test_aes.cpp            # AES unit tests
│   ├── test_rsa.cpp            # RSA tests (planned)
│   ├── test_sha256.cpp         # SHA-256 tests (planned)
│   └── test_chd.cpp            # Perfect hash tests (planned)
│
├── benchmarks/
│   ├── bench_aes.c           # AES performance benchmarks
│   ├── bench_rsa.c           # RSA benchmarks (planned)
│   └── bench_sbox_compare.c  # S-box comparison (planned)
│
├── examples/
│   ├── example_aes.c         # AES usage examples
│   ├── example_rsa.c         # RSA examples (planned)
│   └── example_chd.c         # Perfect hash examples (planned)
│
├── scripts/
│   ├── run_tests.sh          # Test runner script
│   ├── run_benchmarks.sh     # Benchmark runner
│   └── plot_results.py       # Results visualization
│
└── results/
    ├── benchmarks.csv        # Raw benchmark data
    └── *.png                 # Generated graphs