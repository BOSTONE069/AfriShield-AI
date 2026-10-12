# Training data

This directory is separate from `evaluation/data`, which remains held out and must never be used for model fitting, prompt tuning, or threshold selection.

## UCI SMS Spam Collection

Place `sms+spam+collection.zip` in `training/raw/`, then run:

```bash
python training/import_sms_spam.py
```

The importer reads the ZIP without extracting it, validates its structure, removes exact duplicates after normalization, redacts URLs, email addresses, phone-like strings and long numeric codes, and creates a deterministic label-stratified 80/20 split.

Automated redaction is not a guarantee of full anonymization. Every imported record is marked `privacy_review_required: true`; complete human privacy review before publishing the processed data or using it outside a controlled environment.

The UCI SMS Spam Collection contains English binary spam/ham labels. Do not infer more specific threat types from those labels. It is licensed under CC BY 4.0 and requires attribution; full provenance is recorded in `manifests/uci_sms_spam_collection.json`.
