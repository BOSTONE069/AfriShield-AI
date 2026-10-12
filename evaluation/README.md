# AfriShield Evaluation Benchmark

This directory contains a reproducible safety benchmark for AfriShield. Version
1 contains 600 synthetic, anonymized messages. Synthetic cases provide broad,
repeatable coverage but are **not** evidence of field accuracy; production
claims require separately collected, consented, double-reviewed field samples.

## Coverage

- Threat types: phishing, scam, malware, business email compromise,
  misinformation, and difficult benign messages.
- Languages: English, Swahili, Sheng, French, Arabic, Amharic, Hausa, and
  Portuguese.
- Scenarios: M-Pesa, KRA, SACCO, university, NGO, job, loan, SIM-swap,
  delivery, supplier/invoice, public health, election, account, and payment.
- Anonymization: generated URLs use the reserved `.invalid` TLD or
  `example.org`; records contain no names, phone numbers, credentials, or live
  endpoints.

Every record follows [dataset_schema.json](dataset_schema.json) and records its
source and review status. The checked-in synthetic data remains marked
`synthetic_unreviewed` so it cannot be confused with analyst-labelled evidence.

## Reproduce the dataset

```bash
python3 evaluation/generate_dataset.py \
  --size 600 \
  --output evaluation/data/afrishield_eval_v1.jsonl
```

Generation is deterministic. Validation rejects duplicate IDs/messages,
missing languages or classes, unsafe hostnames, personal-data flags, and sizes
outside 300–1,000 records.

## Run the benchmark

```bash
USE_LLM=false USE_LLM_REPORTS=false \
python3 evaluation/evaluate.py \
  --dataset evaluation/data/afrishield_eval_v1.jsonl \
  --output-dir evaluation/results/latest \
  --max-false-negative-rate 0.17 \
  --min-accuracy 0.35
```

Outputs include overall and per-class precision/recall, binary malicious-content
false-negative rate, language/scenario slices, and a confusion matrix. The
weighted error cost assigns 5 points to a false negative, 2 to a wrong malicious
type, and 1 to a false positive.

CI blocks changes that push malicious false-negative rate above 17% or overall
accuracy below 35%. These are regression floors, not product targets. The next
target should be below 5% false negatives while improving multilingual class
accuracy.

## Baselines

The deterministic rules engine produces:

| Metric | rules-1.1.0 | rules-1.2.0 (current) |
|---|---:|---:|
| Records | 600 | 600 |
| Exact threat-type accuracy | 35.50% | 42.17% |
| Macro precision | 54.21% | 82.15% |
| Macro recall | 36.46% | 42.22% |
| Malicious-content recall | 83.75% | 85.00% |
| Malicious false-negative rate | 16.25% (78/480) | 15.00% (72/480) |
| Benign false positives | 105/120 | 71/120 |
| Weighted error cost | 903 | 839 |

rules-1.2.0 matches keywords as whole words, ignores reassurance clauses such
as "no password is required", detects advance-fee scams before generic
phishing, and sends unresolved risk cues to `UNKNOWN_SUSPICIOUS` review rather
than `BENIGN`. English accuracy is 100%; the other languages remain at 29–48%
because the rules only understand English phrasing, and all 72 remaining false
negatives are non-English misinformation. Multilingual classification is the
next priority.

Full language/type slices and confusion matrices are stored in
[`baselines/rules_v2_metrics.json`](baselines/rules_v2_metrics.json) and
[`baselines/rules_v2_confusion_matrix.csv`](baselines/rules_v2_confusion_matrix.csv)
(previous: [`rules_v1_metrics.json`](baselines/rules_v1_metrics.json),
[`rules_v1_confusion_matrix.csv`](baselines/rules_v1_confusion_matrix.csv)).

## Adding real anonymized cases

Field samples should only be added when collection is authorized and retention
requirements are documented. Before inclusion:

1. Remove names, telephone numbers, account identifiers, tokens, and metadata
   that can identify a person.
2. Replace domains with `.invalid` equivalents while preserving relevant URL
   structure.
3. Obtain two independent labels for threat type, language, and scenario.
4. Adjudicate disagreements and set `review_status` to `adjudicated`.
5. Set `source` to `anonymized_field_sample` and confirm
   `contains_personal_data` is false.
6. Keep field data access-controlled if its sharing terms prohibit committing
   it to this repository.

Do not tune rules against a held-out field test partition. Maintain separate
development and final-test sets once field samples are available.

## Analyst feedback loop

Reviewed and adjudicated feedback remains encrypted in SQLite. Evaluate the current rules against those corrections separately from the permanently held-out benchmark:

```bash
DATA_ENCRYPTION_KEY="..." python evaluation/evaluate_feedback.py
```

Results are written under `evaluation/results/feedback/`. Pending records are excluded. The API exposes content-free aggregate metrics to administrators at `GET /api/admin/feedback/metrics`.

Rules, scoring, prompts, model configuration, and local feed files are fingerprinted. After one changes, run the held-out regression and review its false-negative rate before refreshing the accepted fingerprint:

```bash
python evaluation/evaluate.py \
  --max-false-negative-rate 0.17 \
  --min-accuracy 0.35 \
  --update-component-baseline
```

CI runs the regression on every change and fails if the checked-in fingerprint does not match the evaluated components.
