# v3 vendor CVSS: paused (Sun Nov 8, ~2:45 am)

Paused at the user's request, to come back to later. No v3 training is running.

## Done
- `train.py` is written. It runs without errors up to the point it was stopped.
- Leak check finished: `outputs/v3_Vendor_CVSS/leak_check.csv`

| Year (positives) | Column | Present, positives | Present, others | Mean value, positives | Mean value, others |
| --- | --- | --- | --- | --- | --- |
| 2024 (24) | CNA CVSS 3 | 16.7% | 23.3% | 7.45 | 6.72 |
| 2024 (24) | CVSS 4 | 4.2% | 6.7% | 9.30 | 6.47 |
| 2025 (45) | CNA CVSS 3 | 40.0% | 44.1% | 8.27 | 6.68 |
| 2025 (45) | CVSS 4 | 11.1% | 24.9% | 8.70 | 5.91 |

- Presence is lower for positives in both years and for both columns. The direction is stable, but with 24-45 positives the gaps may be noise.
- Where a score is present, positives score higher in both years.

## Not done
- **No model metrics exist.** `results.csv` is only written at the end of the run, so the stopped run saved none.
- It had trained 2024 -> 2025 for all 5 variants, and 2025 -> 2024 for `cna_score` and `cna_fields` (7 of 10 variant/direction pairs), but those numbers are lost.
- Not run: the 2026 coverage-by-month table and top-500 month shares (`final_2026`).

## To resume
`uv run python -m src.v3_Vendor_CVSS.train` reruns everything from the start. It took about 20 minutes for those 7 pairs with the machine busy.
