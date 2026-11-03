# CLAUDE.md - AI-Based Phishing Email Detection & Decision Support System

## 1. Project Overview & Context

This repository houses an intelligent cybersecurity decision support platform combining classical and statistical Artificial Intelligence methodologies to detect, explain, and mitigate email phishing attacks.

- **Academic Context:** Developed for **Artificial Intelligence (CCSAI0301)** at **Noida Institute of Engineering and Technology (NIET)**.
- **Assignment:** AI Project-Based Learning (AI-PBL) / Decision Support System.
- **Global Alignment:** United Nations Sustainable Development Goal 9 (**UN SDG 9: Industry, Innovation & Infrastructure**).
- **Faculty Supervisor:** Dr. Mohd Nazim
- **Student & Author:** Sanjit Kumar (0261DCS013, Section F)
- **Group Members (Group 98, Section F):**
  - **Maneesh Ray** (0261DCS006) — *Team Lead & Solution Architect*
  - **Chandan Kumar** (0261DCS003) — *Search & Optimization Analyst (Units 1 & 2)*
  - **Devanshu** (0261DCS016) — *Heuristic & Decision Intelligence Specialist*
  - **Sanjit Kumar** (0261DCS013) — *Knowledge Representation & Expert System Designer (Unit 3)*
  - **Amresh Singh** (0261DCS005) — *Statistical AI Analyst & Documentation Lead (Unit 4)*

---

## 2. Core Curriculum AI Modules (Units 1 – 4)

| AI Syllabus Unit | Theoretical Foundation | Engineering Implementation | Key Source Files |
| :--- | :--- | :--- | :--- |
| **Unit 1: Problem Solving & Search** | Informed Search, Heuristic Evaluation Function, Greedy Search | Linear weighted feature scoring ($Score = \sum w_i f_i$) with calibrated risk bands and greedy evasion search. | `src/heuristics/heuristic_scorer.py`, `src/heuristics/evasion_search.py` |
| **Unit 2: Adversarial Search** | Two-Player Zero-Sum Games, Minimax Algorithm, Alpha-Beta Pruning | Adversarial game modeling attacker evasion actions (homoglyphs, SSL spoofing) vs. detector defense depth with alpha-beta cutoffs and payoff matrix. | `src/adversarial/minimax_engine.py`, `src/adversarial/tactics.py` |
| **Unit 3: Knowledge Representation** | Horn Clauses, Forward & Backward Chaining, Frames | 13 Horn-clause expert knowledge base; Fixed-point forward-chaining fact inference; Recursive backward-chaining explainable proof tree generator. | `src/expert_system/knowledge_base.py`, `src/expert_system/forward_chaining.py`, `src/expert_system/backward_chaining.py` |
| **Unit 4: Statistical Reasoning** | Bayes' Theorem, Naive Bayes Classifier, Laplace Smoothing ($k=1$) | Log-space Naive Bayes computing posterior $P(\text{Phishing}\mid\vec{f})$, 5-fold cross-validation (mean 96.0%), confusion matrix, and Kaggle dataset streaming loader. | `src/statistical/naive_bayes.py`, `src/statistical/evaluation.py`, `data/kaggle_loader.py` |
| **Integrated Decision Support** | Multi-Factor Consensus, Confidence Scoring & Triage | Blended Decision Support System reconciling heuristic, rule-based, and probabilistic outputs into unified verdicts and mitigation playbooks. | `src/dss/decision_support.py`, `src/dss/batch_analyzer.py` |

---

## 3. Architecture & Repository Layout

```text
├── data/
│   ├── benchmark_dataset.py          # Benchmark dataset generator (60 test, 140 train, 200 total)
│   ├── benchmark_test_60.json        # 60 test emails (28 phishing, 32 legitimate)
│   ├── benchmark_train_140.json      # 140 training emails
│   ├── sample_benchmark_200.json     # 200 total benchmark samples
│   ├── sample_email_list.csv         # 15-sample batch email CSV for instant UI testing
│   └── kaggle_loader.py              # Streaming chunked loader for Phishing_Email.csv
├── models/
│   └── trained_naive_bayes.json      # Pre-trained Naive Bayes log-likelihood parameters
├── src/
│   ├── preprocessing/                # Header regex, MIME parser & 7 core binary feature extractors
│   ├── heuristics/                   # Unit 1: Heuristic risk scorer & evasion search
│   ├── adversarial/                  # Unit 2: Minimax game tree with alpha-beta pruning
│   ├── expert_system/                # Unit 3: 13 Horn clauses, forward & backward chaining engines
│   ├── statistical/                  # Unit 4: Naive Bayes classifier & evaluation metrics
│   ├── dss/                          # Decision Support System & Batch CSV Fleet Analyzer
│   └── server.py                     # Hardened Python standard library HTTP/REST backend
├── web/
│   ├── index.html                    # NIET Similox LMS Portal single-page app shell
│   ├── css/styles.css                # NIET Similox LMS design system
│   └── js/                           # Modular ES6 controllers
│       ├── app.js                    # Shell coordinator, navigation, shortcuts & toasts
│       ├── batch_scanner.js          # CSV dropzone, auto-mapping, KPI cards, table & audit export
│       ├── live_scanner.js           # Real-time single email analyzer, meters & evidence cards
│       ├── adversarial_view.js       # Minimax game tree visualization & tactics matrix
│       ├── proof_tree.js             # Backward chaining proof tree & forward fact logs
│       ├── benchmark_view.js         # Multi-pipeline evaluation table & 5-fold cross-validation
│       └── rules_catalog.js          # 13 Horn-clause searchable knowledge base
├── tests/                            # Unit test suites (11 tests covering all units)
├── phishing_ai.py                    # Root verification script generating Month 2 progress benchmark
├── cli.py                            # Interactive command-line terminal interface
├── run_server.py                     # Entrypoint launching web server on port 8080
└── README.md                         # Project documentation and syllabus mapping
```

---

## 4. UI/UX Design System: NIET Similox LMS

The web frontend is designed as a recreation of the **NIET Similox LMS Portal (`lms.similox.com`)**:

- **Visual Palette:**
  - Canvas Background: `#f8f9fa` (Light educational gray)
  - Card Surfaces: `#ffffff` with subtle borders (`#eaedf1`) and soft elevation shadows
  - Active Pills: `#e8f1fd` background with `#1a73e8` Google/NIET blue typography
  - Primary Brand Blue: `#1a73e8` (Hover: `#1557b0`)
  - Threat Colors: Phishing Red (`#d93025`, bg `#fce8e6`), Suspicious Amber (`#e37400`, bg `#fef7e0`), Clean Green (`#188038`, bg `#e6f4ea`)
- **Typography:**
  - UI Font: `Plus Jakarta Sans`, `-apple-system`, `Roboto`, sans-serif
  - Monospace Font: `JetBrains Mono`, `Consolas`, monospace (for hashes, IP addresses, raw MIME, and metrics)
- **Layout Architecture:**
  - **Left Sidebar:** `NIET` logo, collapse toggle `[|]`, rounded pill nav items, bottom profile badge for **SANJIT KUMAR** (`Section: F`, avatar `SK`).
  - **Top Bar:** Search pill input (`🔍 Click to search emails, indicators, rules...`), `Academic Year 2026-2027` badge, notification bell `🔔`, and chat `💬`.
  - **Top Category Pills:** Quick jump pills for `Fleet CSV Audit`, `Live Email Scanner`, `Adversarial Lab`, `Model Benchmark`, and `Rule Base`.
  - **Hero Welcome Card:** `"Good afternoon, SANJIT KUMAR 👋"`, course supervisor Dr. Mohd Nazim badge, `Launch Threat Scanner ↗`, and student vector illustration.
  - **Today's AI Modules Grid:** 4 course cards modeled after "Today's Classes" referencing Dr. Mohd Nazim, Chandan Kumar, Sanjit Kumar, and Amresh Singh.
  - **5 Embedded Workspaces:** High-throughput batch CSV dropzone with KPIs and pagination, Live single incident analyzer with evidence snippets, Minimax game tree and proof tree lab, Benchmark studio with 5-fold CV, and 13 Horn-clause catalog.
  - **Bottom-Right Widget:** Floating SOC AI Security Assistant bubble (`💬`).

---

## 5. Development & Execution Commands

### 1. Launch Cyber-Defense Web Application
```bash
python3 run_server.py
```
Open **[http://localhost:8080](http://localhost:8080)** in any modern browser.

### 2. Run Automated Test Suite
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

### 3. Run Benchmark Verification Script
```bash
python3 phishing_ai.py
```
Outputs the complete 5-pipeline evaluation matrix and 5-fold cross-validation scores to console and `phishing_output.txt`.

### 4. Launch Interactive CLI
```bash
python3 cli.py
```

### 5. Run Kaggle Dataset Experiment
```bash
python3 notebooks/run_experiments.py
```

---

## 6. Engineering Standards & Architectural Invariants

1. **Zero Third-Party Dependency Rule:**
   - The backend MUST remain runnable on a vanilla Python 3.8+ installation without running `pip install`.
   - Uses exclusively Python standard library modules: `http.server`, `socketserver`, `json`, `re`, `math`, `urllib`, `random`, `sys`, `os`.
2. **Backend Hardening & DOS Protection:**
   - Payload limit enforced at `15 MB` (`MAX_PAYLOAD_BYTES = 15 * 1024 * 1024`) in `src/server.py`.
   - Security headers set on every response:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `X-XSS-Protection: 1; mode=block`
     - `Access-Control-Allow-Origin: *`
   - Health endpoint `/api/health` providing live uptime, rule count, and model readiness telemetry.
   - In-memory caching for immutable benchmark results and rule catalog to prevent redundant cross-validation recomputation.
3. **Frontend Independence:**
   - Pure HTML5, CSS3, and ES6 JavaScript. No bundlers, Node.js, Webpack, or npm dependencies required.
   - Dynamic workspace router with zero page reloads and keyboard shortcuts (`1` to `5` for workspaces, `Esc` for modals).
4. **Git Commit Attribution Convention:**
   - Always append `Co-Authored-By: Claude Code <noreply@anthropic.com>` to git commit messages.
