# cryptographic-algorithms
Experimental study aims in understanding, comparing and implementing of cryptographic algorithms (symmetric, asymmetric encryption, and hash functions) for course of Software Development at University of Bologna


crypto-perfect-hash/
├── README.md
├── Makefile
├── LICENSE
│
├── docs/
│   ├── study.pdf
│   └── slides.pdf                   # Presentation
│
├── src/
│   ├── symmetric/
│   │   ├── aes.h
│   │   ├── aes.c                    # Basic AES-128
│   │   └── aes_sbox_traditional.c   # Traditional 256-byte S-box
│   │
│   ├── asymmetric/
│   │   ├── rsa.h
│   │   └── rsa.c                    # Basic RSA (keygen, encrypt, decrypt)
│   │
│   └── hash/
│       ├── sha256.h
│       ├── sha256.c                 # SHA-256 implementation
│       │
│       ├── chd.h                    # Perfect Hash: CHD
│       ├── chd.c
│       │
│       ├── bdz.h                    # Perfect Hash: BDZ (2-partite only)
│       ├── bdz.c
│       │
│       ├── rank.h                   # Succinct: Rank
│       ├── rank.c
│       │
│       ├── aes_sbox_phf.h          # Integration: AES S-box with PHF
│       └── aes_sbox_phf.c
│
├── tests/
│   ├── test_aes.c
│   ├── test_rsa.c
│   ├── test_sha256.c
│   ├── test_chd.c
│   ├── test_bdz.c
│   ├── test_rank.c
│   └── test_sbox_phf.c             # Compare traditional vs PHF S-box
│
├── benchmarks/
│   ├── bench_aes.c                 # AES performance
│   ├── bench_rsa.c                 # RSA performance
│   ├── bench_chd.c                 # CHD construction + query
│   ├── bench_bdz.c                 # BDZ construction + query
│   └── bench_sbox_compare.c        # Traditional vs PHF S-box
│
├── examples/
│   ├── example_aes.c
│   ├── example_rsa.c
│   ├── example_chd.c               # From slides: 4 IP addresses
│   └── example_bdz.c
│
├── scripts/
│   ├── run_tests.sh
│   ├── run_benchmarks.sh
│   └── plot_results.py             # Generate graphs
│
└── results/
    ├── benchmarks.csv              # Raw data
    ├── construction_time.png       # CHD vs BDZ construction
    ├── space_efficiency.png        # Bits/key comparison
    └── sbox_comparison.png         # Traditional vs PHF S-box
