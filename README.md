# AI-Based Phishing Email Detection & Decision Support System

An intelligent cybersecurity decision support system designed to detect phishing attacks and provide explainable, multi-factor security verdicts using classical and statistical Artificial Intelligence methodologies.

Developed for **Artificial Intelligence (CCSAI0301)** at **Noida Institute of Engineering and Technology (NIET)** in alignment with **United Nations Sustainable Development Goal 9 (SDG 9: Industry, Innovation & Infrastructure)**.

---

## 👥 Team Information (Team Aahvaan - Group 1, Section F)
- **Maneesh Ray** (0261DCS006) — *Team Lead & AI Solution Architect*: End-to-end pipeline architecture, dataflow orchestration, and integration.
- **Chandan Kumar** (0261DCS003) — *Search Algorithm & Optimisation Analyst*: Informed heuristic scoring functions, weight calibration, and minimal evasion search.
- **Devanshu** (0261DCS016) — *Heuristic & Decision Intelligence Specialist*: Multi-module decision blending logic and threshold reconciliation.
- **Sanjit Kumar** (0261DCS013) — *Knowledge Representation & Expert System Designer*: 13 Horn-clause knowledge base, forward chaining inference engine, and backward chaining proof tree generator.
- **Amresh Singh** (0261DCS005) — *Statistical AI Analyst & Documentation Lead*: Naive Bayes classifier with Laplace smoothing, 5-fold cross-validation, and metrics analysis.

**Faculty Supervisor**: Dr. Mohd Nazim

---

## 🎯 Curriculum & Syllabus Module Mapping (Units 1 – 4)

| AI Syllabus Unit | Theoretical Concept | Project Implementation |
| :--- | :--- | :--- |
| **Unit 1: Problem Solving & Search** | Informed Search, Heuristic Evaluation Function, Greedy Search | Weighted feature scoring engine for rapid risk triage; Greedy minimal evasion path search. |
| **Unit 2: Adversarial Search** | Game Playing, Minimax Algorithm, Alpha-Beta Pruning | Two-player zero-sum game modeling attacker evasion tactics (homoglyphs, obfuscation) vs. detector defense depth. |
| **Unit 3: Knowledge Representation** | Horn Clauses, Forward & Backward Chaining, Frames | 13 Horn-clause knowledge base; Forward chaining for fact derivation; Backward chaining for explainable proof trees. |
| **Unit 4: Statistical Reasoning** | Bayes' Theorem, Naive Bayes, Laplace Smoothing, Evaluation | Log-space Naive Bayes classifier; posterior probability $P(\text{Phishing}\mid\vec{f})$; 5-fold cross-validation & confusion matrix. |

---

## 🏗️ System Architecture

```text
                                  ┌──────────────────────┐
                                  │ Incoming Raw Email   │
                                  └──────────┬───────────┘
                                             │
                                  ┌──────────▼───────────┐
                                  │ Preprocessing Module │
                                  │ (Regex, MIME Parser) │
                                  └──────────┬───────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        │  Extracted 7 Core Binary Indicators     │
                        └────────────────────┬────────────────────┘
                                             │
     ┌──────────────────────┬────────────────┴────────────────┬──────────────────────┐
     │                      │                                 │                      │
┌────▼─────────────┐ ┌──────▼─────────────┐       ┌───────────▼───────────┐ ┌────────▼───────────┐
│ Unit 1: Heuristic│ │ Unit 2: Adversarial│       │ Unit 3: Expert System │ │ Unit 4: Statistical │
│ Weighted Scoring │ │ Minimax Alpha-Beta │       │ Forward / Backward    │ │ Naive Bayes Engine  │
│ Baseline Scorer  │ │ Game Search Tree   │       │ Horn Clause Proof Tree│ │ Posterior P(Phish)  │
└────┬─────────────┘ └──────┬─────────────┘       └───────────┬───────────┘ └────────┬───────────┘
     │                      │                                 │                      │
     └──────────────────────┼─────────────────────────────────┴──────────────────────┘
                            │
               ┌────────────▼──────────────────────────┐
               │ Integrated Decision Support System    │
               │ (Reconciliation, Confidence & Advice) │
               └────────────┬──────────────────────────┘
                            │
          ┌─────────────────┴─────────────────┐
          │                                   │
┌─────────▼───────────────┐       ┌───────────▼───────────┐
│ Cyber-Defense Dashboard │       │ Interactive Terminal  │
│ (Web UI on Port 8080)   │       │ CLI & Console Reports │
└─────────────────────────┘       └───────────────────────┘
```

---

## 🔬 Core Algorithms & Methodologies

### 1. Preprocessing & Feature Extraction
Extracts 7 core binary indicators identified in Month 1 & Month 2 specifications:
1. `reply_to_mismatch`: Sender domain differs from Reply-To header.
2. `ip_in_url`: URL uses direct IPv4 / IPv6 format rather than hostname.
3. `suspicious_tld`: URL/domain utilizes high-risk TLDs (`.xyz`, `.top`, `.club`, `.ru`, etc.).
4. `urgency_words`: Coercive psychological trigger keywords in body text.
5. `executable_attachment`: Dangerous file payloads (`.exe`, `.scr`, `.bat`, `.iso`, etc.).
6. `no_https`: Link lacks SSL/TLS encryption (`http://`).
7. `long_url`: URL length exceeds 75 characters.

### 2. Unit 1: Informed Heuristic Search
Computes weighted risk score:
$$\text{Score} = \sum_{i} w_i \cdot f_i$$
- Weights: 3 for `reply_to_mismatch`, `ip_in_url`, `executable_attachment`; 2 for `urgency_words`, `suspicious_tld`; 1 for `no_https`, `long_url`.
- Thresholds: Score $\ge 5 \to \text{Phishing}$, Score $\ge 3 \to \text{Suspicious}$, Score $< 3 \to \text{Safe}$.

### 3. Unit 2: Adversarial Search (Minimax with Alpha-Beta Pruning)
Models cyber threats as a two-player game:
- **Attacker (MAX Player)**: Applies evasion perturbations (homoglyphs, SSL masquerade, urgency dilution, attachment cloaking) to maximize evasion utility minus modification cost.
- **Detector (MIN Player)**: Deploys inspection countermeasures (deep URL expander, sandbox detonation, NLP intent parser, zero-trust thresholds) to minimize attacker evasion while bounding computation overhead.
- **Alpha-Beta Pruning**: Prunes redundant evaluation subtrees where $\beta \le \alpha$, accelerating real-time defense.

### 4. Unit 3: Knowledge Representation & Expert System
Encodes 13 Horn Clauses over email facts:
- **Forward Chaining**: Fixed-point data-driven deduction inferring intermediate predicates (`spoofed_sender`, `bad_link`, `dangerous_file`) until reaching final conclusions.
- **Backward Chaining**: Goal-directed proof engine querying `phishing` and constructing an explainable **Proof Tree**:
  > *"Phishing proved via Rule 7: spoofed sender (reply-to mismatch) and bad link (suspicious TLD)"*

### 5. Unit 4: Statistical Reasoning (Naive Bayes)
Calculates posterior probability in log space with Laplace smoothing ($k=1$):
$$\log P(\text{Phishing} \mid \vec{f}) \propto \log P(\text{Phishing}) + \sum_{i} \log P(f_i \mid \text{Phishing})$$
Evaluated via 5-Fold Cross-Validation, Precision, Recall, and Confusion Matrix.

---

## 📊 Benchmark Results (Month 2 Progress Report Verification)

Evaluation on the 60 test emails (28 Phishing, 32 Legitimate):

| Detector Pipeline | Accuracy | Precision | Recall | False + | False - |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Heuristic baseline** | **0.883** | **0.800** | **1.000** | 7 | 0 |
| **Rule base (flagged)** | **0.867** | **0.833** | **0.893** | 5 | 3 |
| **Rule base (Phishing only)** | **0.883** | **0.862** | **0.893** | 4 | 3 |
| **Naive Bayes ($\ge 0.5$)** | **0.883** | **0.800** | **1.000** | 7 | 0 |
| **Combined DSS (flagged)** | **0.883** | **0.800** | **1.000** | 7 | 0 |

- **Naive Bayes 5-Fold Cross-Validation**: `0.925, 0.950, 0.950, 1.000, 0.975` (Mean: **0.960**)
- **Kaggle Dataset Streaming**: Compatible with large-scale 175,000+ email dataset (`Phishing_Email.csv`).

---

## 🚀 How to Run the Project

### Prerequisites
- Python 3.8+ (Zero third-party pip dependencies required; uses Python standard library `re`, `math`, `random`, `http.server`, `json`).

### 1. Run Month 2 Benchmark & Report Output
```bash
python3 phishing_ai.py
```
*(Executes all 5 detectors, displays the evaluation table, runs 5-fold cross-validation, and saves output to `phishing_output.txt`).*

### 2. Launch Interactive Terminal CLI
```bash
python3 cli.py
```
*(Interactive menu to test preset attack emails, paste custom emails, run benchmarks, or evaluate on Kaggle).*

### 3. Launch Cyber-Defense Web Application
```bash
python3 run_server.py
```
Open **[http://localhost:8080](http://localhost:8080)** in your browser to access:
- **Bulk Email CSV Threat Intelligence & Audit Scanner**: Upload any CSV email list (auto-detects sender, subject, body columns) to generate instant threat audits, 5 KPI executive metrics, indicator prevalence charts, filtered investigation tables, and downloadable CSV audit reports.
- **Live Email Analyzer**: Real-time feature detection, risk index gauge, explainable deduction reasoning, and actionable security advisories.
- **Adversarial Security Matrix**: Minimax game tree and evasive attacker tactics sensitivity matrix.
- **Algorithmic Evaluation Studio**: Live verification tables comparing Heuristic, Expert System, Naive Bayes, and Combined DSS.

### 4. Run Automated Test Suite
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 📁 Repository Structure
```text
├── data/
│   ├── benchmark_dataset.py          # Benchmark dataset generator
│   ├── benchmark_train_140.json      # 140 training sample emails
│   ├── benchmark_test_60.json        # 60 test sample emails
│   ├── sample_benchmark_200.json     # Full 200 benchmark sample emails
│   ├── sample_email_list.csv         # 15-sample batch email CSV for instant testing
│   └── kaggle_loader.py              # Streaming loader for Phishing_Email.csv
├── models/
│   └── trained_naive_bayes.json      # Serialized Naive Bayes model parameters
├── src/
│   ├── preprocessing/                # Header parsing & 7-feature extraction
│   ├── heuristics/                   # Unit 1: Heuristic baseline risk scorer
│   ├── adversarial/                  # Unit 2: Minimax & Alpha-Beta game search
│   ├── expert_system/                # Unit 3: Horn clauses & proof tree engines
│   ├── statistical/                  # Unit 4: Naive Bayes & evaluation metrics
│   ├── dss/                          # Blended Decision Support System & Batch CSV Analyzer
│   └── server.py                     # Built-in REST API & static web server
├── web/
│   ├── index.html                    # Single-page SOCRadar enterprise blue/white dashboard
│   ├── css/styles.css                # Enterprise SOCRadar design system & typography
│   └── js/                           # Real-time scan controllers & CSV export engines
├── tests/                            # Unit and integration test suites
├── notebooks/
│   └── run_experiments.py            # Feature prevalence & log-odds importance
├── phishing_ai.py                    # Root script referencing Month 2 progress report
├── cli.py                            # Interactive command-line interface
├── run_server.py                     # Web server launcher
└── README.md                         # Comprehensive documentation
```
