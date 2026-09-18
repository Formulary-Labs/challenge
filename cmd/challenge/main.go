// challenge applies 10 deterministic interrogation patterns to compliance artifacts
// to surface failures before human review.
//
// Usage:
//
//	challenge <artifact.json> [flags]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Formulary-Labs/challenge/interrogate"
	"github.com/Formulary-Labs/substrate/exit"
	"github.com/Formulary-Labs/substrate/provenance"
)

const version = "0.1.0"

func main() {
	var (
		severityFlag = flag.String("severity-threshold", "low", "Minimum severity to include: critical, high, medium, low")
		programFlag  = flag.String("program", "", "Program slug for provenance logging")
		fmtFlag      = flag.String("format", "json", "Output format: json (default), md")
		versionFlag  = flag.Bool("version", false, "Print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Printf("challenge version %s\n", version)
		os.Exit(exit.OK)
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, `{"error": "artifact path required", "code": 2}`)
		flag.Usage()
		os.Exit(exit.ToolError)
	}

	artifactPath := flag.Arg(0)
	a, err := interrogate.Load(artifactPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error": %q, "code": 2}`+"\n", err.Error())
		os.Exit(exit.ToolError)
	}

	report := interrogate.ApplyAll(a, artifactPath, *severityFlag)

	switch *fmtFlag {
	case "md":
		printMD(report)
	default:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report) //nolint:errcheck
	}

	// Exit 1 if any critical findings.
	hasCritical := report.OverallPosture == interrogate.Critical
	hasHigh := report.OverallPosture == interrogate.High

	if *programFlag != "" {
		_ = provenance.Write("logs/provenance.jsonl", provenance.Entry{
			Spec:        "functions/compliance-redteam-spec.md",
			Output:      artifactPath,
			OutputType:  "other",
			Program:     *programFlag,
			Purpose:     fmt.Sprintf("challenge: %d findings (%s posture) on %s", len(report.Findings), report.OverallPosture, artifactPath),
			Reusability: provenance.Instance,
			QualityGate: provenance.Pass,
			Tool:        "challenge",
			ToolVersion: version,
		})
	}

	if hasCritical || hasHigh {
		os.Exit(exit.Validation)
	}
}

func printMD(r interrogate.Report) {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "# Challenge Report\n\n")
	fmt.Fprintf(sb, "**Artifact:** %s  \n", r.Artifact)
	if r.Framework != "" {
		fmt.Fprintf(sb, "**Framework:** %s  \n", r.Framework)
	}
	fmt.Fprintf(sb, "**Generated:** %s  \n", r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(sb, "**Overall Posture:** %s  \n", strings.ToUpper(string(r.OverallPosture)))
	fmt.Fprintf(sb, "**Findings:** %d\n\n", len(r.Findings))

	if len(r.Findings) == 0 {
		fmt.Fprintf(sb, "No findings at the configured severity threshold.\n\n")
	} else {
		fmt.Fprintf(sb, "| ID | Pattern | Severity | Control | Observation |\n|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			obs := f.Observation
			if len(obs) > 80 {
				obs = obs[:77] + "..."
			}
			fmt.Fprintf(sb, "| %s | %s | %s | %s | %s |\n", f.ID, f.PatternID, f.Severity, f.ControlID, obs)
		}
		fmt.Fprintln(sb)

		for _, f := range r.Findings {
			fmt.Fprintf(sb, "### %s — %s\n\n", f.ID, f.PatternID)
			fmt.Fprintf(sb, "**Severity:** %s  \n", f.Severity)
			if f.ControlID != "" {
				fmt.Fprintf(sb, "**Control:** %s  \n", f.ControlID)
			}
			fmt.Fprintf(sb, "**Observation:** %s  \n\n", f.Observation)
			fmt.Fprintf(sb, "**Risk:** %s  \n\n", f.Risk)
			fmt.Fprintf(sb, "**Recommendation:** %s\n\n", f.Recommendation)
		}
	}

	fmt.Fprintf(sb, "---\n\n*%s*\n", r.Disclaimer)
	fmt.Print(sb.String())
}

func usage() {
	fmt.Fprintln(os.Stderr, `challenge — adversarial compliance artifact interrogation

Usage:
  challenge <artifact.json> [flags]

Flags:
  --severity-threshold string   Minimum severity: critical, high, medium, low (default: low)
  --program string              Program slug for provenance logging
  --format string               Output format: json (default), md
  --version                     Print version and exit

Exit codes:
  0  No findings at critical or high severity
  1  Critical or high findings present
  2  Tool error

Examples:
  challenge assessment.json
  challenge assessment.json --severity-threshold medium --format md
  assay --framework iso27001 --product docs/ > assessment.json && challenge assessment.json`)
}
