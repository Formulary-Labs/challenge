# challenge

Ten patterns. Any one of them is what your auditor asks first. Run them yourself before they do.

```bash
go get github.com/Formulary-Labs/challenge
```

## What it does

`challenge` applies 10 deterministic interrogation patterns to a compliance program artifact — a SOA, control catalog, risk assessment, or `assay` output. Each pattern flags a structural observation a qualified subject matter expert should investigate before the artifact leaves the building.

`challenge` does not make compliance determinations. It surfaces the questions. Same input, same output, every run.

## Input

`challenge` reads a `ChallengeArtifact` — a JSON file containing your compliance artifact. It accepts the gemara `ControlCatalog` shape and a richer SOA/assessment shape (the output of `assay`).

```go
import "github.com/Formulary-Labs/challenge/interrogate"

report, err := interrogate.ApplyAll(
    artifact,            // interrogate.ChallengeArtifact
    "output/soa.json",   // artifact path — included in provenance
    "medium",            // severity threshold: omit findings below this level
)
```

## Interrogation patterns

| ID | Severity | What it detects |
|---|---|---|
| `RESTATEMENT_TEST` | High | Implementation text ≥65% similar to requirement text (Jaccard similarity) |
| `STAKEHOLDER_ABSENCE_TEST` | High/Med | Single owner on ≥50% of controls; any controls with no owner |
| `EVIDENCE_TRACEABILITY_TEST` | High | Evidence path points to a non-existent file; `satisfied` controls with no evidence reference |
| `INHERITANCE_VALIDATION_TEST` | High | Inherited controls with no `validated_for` field |
| `EXCEPTION_HONESTY_TEST` | Medium | ≥10 controls, zero exceptions, zero `not_satisfied` determinations |
| `CADENCE_SUSTAINABILITY_TEST` | High | Any control past its `review_cadence_days` since `last_reviewed` |
| `RISK_APPETITE_TEST` | Medium | Fewer than 5% of scored controls have a risk score ≥ 6 |
| `LEADERSHIP_REALITY_TEST` | High/Med | Leadership controls with no owner or a generic role title |
| `SCOPE_BOUNDARY_TEST` | High | Excluded controls with no `exclusion_justification` |
| `OPERATIONAL_REALITY_TEST` | Low | Implementation text with ≥40% passive voice constructions |

### Severity threshold

Pass a threshold to `ApplyAll` to suppress findings below a minimum severity:

```go
// High and critical only — for a quick pre-submission check
interrogate.ApplyAll(artifact, path, "high")

// All findings including low — for a thorough internal review
interrogate.ApplyAll(artifact, path, "low")
```

## Output

```json
{
  "artifact": "output/soa.json",
  "framework": "iso27001",
  "generated_at": "2026-09-18T00:00:00Z",
  "overall_posture": "high",
  "findings": [
    {
      "id": "RT-001",
      "pattern_id": "RESTATEMENT_TEST",
      "severity": "high",
      "control_id": "A.5.1",
      "observation": "Implementation text is 71% similar to the requirement statement.",
      "risk": "The control may not represent a genuine implementation.",
      "recommendation": "Replace with a specific description of the implemented control measure."
    }
  ],
  "patterns_run": ["RESTATEMENT_TEST", "STAKEHOLDER_ABSENCE_TEST", "..."],
  "disclaimer": "All findings require validation by a qualified compliance SME before action is taken."
}
```

`overall_posture` is the highest severity finding present. If no findings triggered, it is `"none"`.

## Reading the results

Each finding has three fields worth understanding:

**`observation`** — what the pattern detected, stated as a measurement ("71% similar", "3 controls past cadence by >90 days").

**`risk`** — what this observation could mean from an audit perspective.

**`recommendation`** — a specific corrective action, not a general suggestion.

The `disclaimer` in every output is not boilerplate. `challenge` is a structural scanner. It cannot verify intent, business context, or compensating controls. All findings require human review before driving decisions.

## When to run it

`challenge` consumes **`assay assemble` JSON**, not gemara YAML and not raw unfinished assay state.

```bash
# 1. Initialize assessment from a ControlCatalog (local fixture path)
assay init --catalog path/to/control-catalog.yaml \
  --product-name "MyProduct" --product-version "1.0" \
  --framework iso42001 --program myprogram

# 2. Fill batches (human or agent), then validate
assay batch --state data/myprogram/assessments/<run>-state.json
assay validate --state data/myprogram/assessments/<run>-state.json \
  --responses responses.json

# 3. Assemble final JSON (this is the challenge input)
assay assemble --state data/myprogram/assessments/<run>-state.json

# 4. Interrogate the assembled assessment JSON
challenge data/myprogram/assessments/<product>-<framework>-assessment.json \
  --program myprogram --format md --severity-threshold medium
```

Synthetic Formulary testdata (not gemara docs): `challenge/testdata/good-assessment.json` and `challenge/testdata/assay-assemble-shape.json`.

```bash
challenge testdata/good-assessment.json --format md
```

`Load` accepts either:
- `ChallengeArtifact` with `controls` as a **JSON array**, or
- assay `AssessmentState` / assemble output with `controls` as a **map keyed by control ID**

Formulary does not ship gemara framework catalogs. Point `--catalog` / assay `--catalog` at your own private ControlCatalog when needed.

Run it on a SOA/assessment after any major program change to check for structural regressions before the next cycle.

## Catalogs

The `--catalog` flag enables inheritance validation against a gemara `ControlCatalog`. See [CATALOGS.md](https://github.com/Formulary-Labs/.github/blob/main/CATALOGS.md) for known upstream catalog sources.

## License

Apache License 2.0
