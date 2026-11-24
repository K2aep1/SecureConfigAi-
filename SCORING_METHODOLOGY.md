# SecureConfigAI Scoring Methodology

SecureConfigAI intentionally separates four different concepts: security posture, assessment coverage, compliance, and contextual risk.

## 1. Security Posture

The authoritative posture score is control-weighted:

`Posture = Σ(weight × compliant_state) / Σ(assessed_applicable_weight) × 100`

Where `compliant_state = 1` and `non_compliant = 0`.

`not_applicable` is excluded. `unknown` and `error` are never counted as compliant.

## 2. Assessment Coverage

`Coverage = assessed_applicable_weight / total_applicable_weight × 100`

Coverage prevents an apparently perfect score from being interpreted as a complete assessment when evidence is missing.

## 3. Compliance

Compliance is calculated from applicable assessed controls rather than the number of findings. The current implementation uses an unweighted control compliance percentage, while posture uses control weights.

## 4. Risk

Risk is intentionally independent from posture. Only `non_compliant` controls contribute;
`unknown`, `error` and `not_applicable` never do — missing evidence must not inflate risk
any more than it may inflate posture.

Each failing control has a normalised impact in `0..1`:

```
impact_i = severity_impact_i × category_exposure_i × asset_criticality / 125
```

* `severity_impact` — 5 critical, 4 high, 3 medium, 2 low, 1 informational
  (`severity_impact` in the baseline pack)
* `category_exposure` — 1–5 per category, published in the baseline pack
  (Network Security 5; Firewall, Authentication, Account Security, Endpoint Protection and
  Updates 4; System Hardening, Registry Hardening, Access Control, Device Security and
  Services 3)
* `asset_criticality` — a real 1–5 input per device (`devices.criticality`), clamped to
  that range, so the factor is not inert

Impacts are combined with a **noisy-OR** (independent-failure) model:

```
risk = round(100 × (1 − Π (1 − L × impact_i)))     over failing controls i
```

with `L = 0.5` (`single_control_likelihood` in the baseline pack) and each term capped at
`0.95`. Consequences that matter:

* the scale is bounded to `0..100` **and reachable in every band**, so the `critical`
  threshold (80) is attainable instead of dead code;
* adding another failure can never lower the score (monotonic);
* one severe failure on a criticality-5 asset can reach the critical band on its own,
  which is why the per-control term is capped rather than summed.

Worked examples (28-control baseline, weight 217):

| Scenario | Risk | Level |
|---|---|---|
| No failing controls | 0 | low |
| `NET-SMB1-001` only, criticality 1 | 8 | low |
| `NET-SMB1-001` only, criticality 5 | 40 | high |
| Every control failing, criticality 1 | ≥ 99 | critical |

Every threshold and constant above lives in
`backend/app/data/baseline/global_baseline_v1.json` and is validated at startup, so the
model can be reviewed and tuned as data rather than as code.

This is the defined SecureConfigAI methodology. It is not represented as an official NIST,
CIS, or Microsoft formula.

## 5. Evidence quality

Evidence quality is derived from assessment coverage and unresolved control states:

- `high`: 100% coverage and no unknown/error controls
- `medium`: at least 75% coverage
- `low`: partial coverage below 75%
- `unavailable`: no assessed evidence

## 6. Why findings are not the denominator

A finding is an outcome of a control failure. Counting findings as controls causes scores to change merely because a control produces more or fewer findings. SecureConfigAI therefore evaluates stable controls first and derives findings from non-compliant controls.
