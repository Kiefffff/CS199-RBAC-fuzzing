# BAC Fuzzing in RBAC Systems

**Thesis Title:** Detecting Broken Access Control in RBAC Systems Using Specialized API Fuzzing Techniques

**Author:** Seth Limbo  
**Institution:** Department of Computer Science, University of the Philippines Diliman  
**Course:** CS 199 - Computer Security Laboratory  
**Date:** May 2026

## Abstract

This repository contains the source code, configurations, and data for the thesis evaluating whether state-aware API fuzzers (Schemathesis, EvoMaster) detect more Broken Access Control (BAC) vulnerabilities in RBAC systems compared to generic mutation-based fuzzers (OWASP ZAP).

## Repository Structure

- `scripts/` - Python scripts for statistical analysis and graph generation
- `configs/` - Fuzzer configuration files
- `openapi-specs/` - Minimal OpenAPI specifications created for testing
- `data/` - Raw experimental data (CSV files)
- `results/` - Generated graphs and statistical outputs
- `documentation/` - Setup and reproduction guides

## Target Systems

- **OWASP Juice Shop v17.2.0** - Binary RBAC
- **OWASP crAPI v2.0.0** - Hierarchical RBAC
- **VAmPI** - Token-based RBAC
- **Strapi v4.15+** - Production-grade CMS (secure baseline)

## Fuzzers Evaluated

- OWASP ZAP 2.17.0 (Generic, mutation-based)
- Schemathesis 4.10.2 (State-aware, property-based)
- EvoMaster 5.1.0 (State-aware, search-based)

## Key Findings

- State-aware fuzzers detected **9 BAC vulnerabilities** across vulnerable targets
- Generic fuzzer (ZAP) detected **0 vulnerabilities**
- Statistical significance: **p = 0.021** (Mann-Whitney U test)
- Effect size: **Cliff's δ = 0.67** (large effect)
- All tools exhibited **78-100% false positive rates**

## Reproduction Instructions

### Prerequisites

- Python 3.13+
- Docker v28.4.0+
- Node.js v20.x
- Java OpenJDK 17

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/Kiefffff/CS199-RBAC-fuzzing.git
   cd CS199-RBAC-fuzzing
