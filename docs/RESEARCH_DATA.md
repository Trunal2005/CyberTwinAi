# Local real-dataset research workflow

The default synthetic evaluation remains reproducible. The additional CLI evaluates a user-supplied CSV; it does not download data or require accounts, APIs or paid compute.

## Dataset considered

[UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) publishes captured traffic and labeled CICFlowMeter CSV features. It is a 2017 testbed corpus, not representative evidence of present production detection. Consult the publisher's current license/usage terms before obtaining or redistributing it; raw captures can be large and must not be committed here. This repository ships no third-party dataset.

Feature schema differences, labeling quality, duplicate rows, attack/day confounding and host/session leakage require care. A random row split is inadequate when related flows occur in both partitions. The CLI requires an independent capture/host/day grouping column supplied and documented by the researcher. Merely making arbitrary row groups does not establish independence. Small numbers of days can also entangle group and class; the CLI rejects splits lacking either class. It does not repeatedly select a split based on test performance.

## Schema and command

Normalized `network-core-v1` columns are `duration` (seconds), `packets`, `bytes`, `dst_port`, plus binary/class `Label` and your grouping column. `BENIGN`, `normal`, `0` map to benign; other nonmissing labels map to suspicious. Original class names are retained only in the source CSV; this evaluation is binary.

Alternatively, documented CIC-style columns are mapped explicitly: `Flow Duration` microseconds → seconds; `Total Fwd Packets + Total Backward Packets` → packets; `Total Length of Fwd Packets + Total Length of Bwd Packets` → bytes; `Destination Port` → dst_port. Column whitespace is stripped. Missing/infinite/negative numeric features or missing group/label rows are dropped with counts. Identical feature rows are removed; contradictory labels for identical features reject the evaluation. Limits are 100 MB and 100,000 rows, with oversize inputs rejected rather than silently sampled.

```powershell
.\.venv\Scripts\python.exe -m backend.research_ml C:\datasets\owned-subset.csv --group-column capture_group --label-column Label --provenance "CICIDS2017 locally prepared subset with documented capture-day grouping" --output data/research-model.joblib
```

GroupShuffleSplit uses seed42 and a 25% held-out group selection. Test rows are not necessarily 25% of all rows. Features contain neither addresses, labels, IDs nor group values. Logistic regression scaling fits only training rows. Majority and Random Forest compare on the same held-out groups. Reports include input SHA256, group membership, class distribution, invalid/duplicate counts, sample sizes, confusion matrix, precision/recall/F1, false-positive and false-negative rates, measured fit/inference time and feature importance. Rule IDS remains an independent operational baseline: this four-feature table cannot establish authentication or original signature evidence.

Artifacts default to a separate ignored research path and do not replace the running model. Runtime admission also requires explicit feature-schema alignment: sensor byte counters, captured IP bytes and CICFlowMeter counters are not assumed equivalent. An explicit `feature_schema: network-core-v1` prediction request is only appropriate after independently validating the feature mapping. Selected raw-log/PCAP predictions refuse automatic use of a research artifact; the synthetic benchmark remains available for the normal demonstration. Missing fields use disclosed training-only means, never silent arbitrary zeros. Imputed values are not measured data.

## Evidence status

The CLI is regression-tested using a generated fixture with six independent test groups; this verifies code behavior only. **No CICIDS2017 data was supplied or downloaded and no real-dataset score is claimed.** Real dataset quality, licenses, independence and external validation remain researcher responsibilities. Synthetic predictions are uncalibrated. Neither synthetic nor research model output independently authorizes a real firewall action.
