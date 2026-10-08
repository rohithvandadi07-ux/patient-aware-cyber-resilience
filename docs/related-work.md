# Related work and research positioning

This document records the literature basis for the project's positioning and
the evidence that the targeted gap is open. It is maintained alongside the
implementation so that the paper's related-work section is traceable to
sources rather than reconstructed at writing time.

> **Claim discipline.** No "first-ever" claim is made anywhere in this
> project. The positioning below is a *gap* argument supported by published
> reviews, not a novelty assertion.

---

## 1. Positioning statement

**Prior IoMT security work overwhelmingly stops at detection.** Where
response is addressed, it is typically alert-based, treated as future work,
or implemented as an undifferentiated mitigation action that does not reason
about what the defended asset *does for a patient*.

This project targets that gap:

> Autonomous cyber-defense for safety-critical IoMT that selects responses by
> jointly evaluating cybersecurity risk, clinical criticality and the clinical
> impact of the response itself, under deterministic safety policy with
> human-in-the-loop escalation and verified recovery.

---

## 2. Evidence that the gap is open

The strongest support comes from a 2026 systematic gap analysis of IoT
intrusion detection, which independently identifies each element of our
contribution as missing from prior work.

**Sallam, S.; El Barachi, M.; Li, N.** "Intrusion Detection on the Internet of
Things: A Comprehensive Review and Gap Analysis Toward Real-Time,
Lightweight, Adaptive, and Autonomous Security." *IoT*, 2026, 7(1), 16.
<https://doi.org/10.3390/iot7010016>

Findings relevant to this project:

| Their finding | Our corresponding component |
|---|---|
| "Mitigation features are often absent, adaptability is rarely implemented" | Full closed loop: detection → decision → response → recovery |
| Calls for work that moves "beyond accuracy-focused models" toward "autonomous solutions that incorporate mitigation" | Controlled-autonomy response orchestration |
| "Since incorrect automated actions could lead to service disruptions or physical harm, we carefully assess mitigation measures" | Response-impact assessment + deterministic safety policy |
| "unverified autonomous actions could pose operational or ethical challenges, especially in safety-critical contexts" | Human approval gate for high clinical impact; recovery verification |
| Reviewed systems described as "detection-only, with mitigation noted as future work", "alert-based, lacks autonomy", "Response Unit reports risks or triggers alarms, not automated mitigation" | The baseline configurations we compare against (see `docs/experiments.md`) |
| "Mitigation procedures are conducted separately and are not integrated into the system workflow" | One integrated platform, not adjacent subsystems |
| Defines an autonomy scale where L1 = suggests mitigation for "operator approval" | Our policy engine implements graded autonomy explicitly |
| **Impact-aware response is *not analysed* in the reviewed literature**; the review notes context-awareness as desirable but does not find work weighing service impact in response decisions | **Patient-aware dual-risk decision making — the central contribution** |

The last row is the most important: an independent systematic review
searching this literature did not find work that weighs the impact of the
response when choosing it. That is the specific hole this project fills.

### Supporting reviews

- **Alhamam, N.; Hafizur Rahman, M. M.; Aljughaiman, A.** "A Comprehensive
  Review on Cybersecurity of Digital Twins: Issues, Challenges, and Future
  Research Directions." *IEEE Access*, 2025, 13, 45106.
  DOI: 10.1109/ACCESS.2025.3545004

  Relevant stated gaps: "the reliability of DT software for autonomous
  control systems is essential, considering the escalating use of DT software
  in directly controlling physical systems"; and a call for "automation in
  identifying, quantifying, and reevaluating cyber risks." Also notes "the
  absence of comprehensive datasets" as an impediment, and that physical-system
  intrusion detection via virtual replicas "remains largely unexplored."

  *Use:* supports the autonomous-control-reliability and risk-quantification
  motivation. Note this is a review of **digital twins**, a related but
  distinct paradigm from our simulation environment; cite it for the gap
  statements, not as a methodological precedent.

- **Dadkhah, S.; Neto, E. C. P.; Ferreira, R.; Molokwu, R. C.; Sadeghi, S.;
  Ghorbani, A. A.** "CICIoMT2024: Attack Vectors in Healthcare Devices — A
  Multi-Protocol Dataset for Assessing IoMT Device Security." *Internet of
  Things*, 2024, 28. (Primary dataset paper — see `docs/datasets.md`.)

### Reviewed and set aside

- **Eneyew, D. D.; Capretz, M. A. M.; Bitsuamlak, G. T.** "Toward
  Smart-Building Digital Twins: BIM and IoT Data Integration." *IEEE Access*,
  2022, 10, 130487. DOI: 10.1109/ACCESS.2022.3229370

  Smart *buildings*, BIM/IoT semantic interoperability. No security content,
  no attack model, no dataset, no detection metrics. Not usable as a baseline
  or a dataset source. Retained only as an optional citation if the
  simulation-environment architecture needs a precedent for multi-layer
  data integration.

---

## 3. Comparison strategy

Because no prior system performs patient-aware response selection, there is
no directly comparable published system. The comparison is therefore
two-tracked, and the paper must state this split explicitly.

### Track A — detection layer, versus published benchmarks

Our detection component is compared against published results on a shared
public dataset (CICIoMT2024) using that dataset's own splits. The purpose is
**calibration, not novelty**: it demonstrates that our detection layer is
competitive with the state of the art, so that any difference in end-to-end
outcomes is attributable to the decision layer rather than to a weak
detector.

Published reference points on CICIoMT2024 (see `docs/datasets.md` for the
full table and provenance):

| Task | Model | Accuracy | Source |
|---|---|---|---|
| Binary | XGBoost (top-15 IG features) | 0.997 | SCITEPRESS 2025 |
| 6-class | XGBoost (top-15 IG features) | 0.977 | SCITEPRESS 2025 |
| 19-class | XGBoost (top-15 IG features) | 0.967 | SCITEPRESS 2025 |

Note that binary detection on this dataset is close to saturated — multiple
papers report F1 > 0.99 with fewer than five features. **This is an argument
for our thesis, not against it:** if detection is effectively solved, the
remaining research value lies in what the system *does* after detecting,
which is precisely our contribution. The paper should make this point
explicitly rather than competing for a fourth decimal place.

### Track B — decision layer, versus internal baselines and ablations

The patient-aware decision layer cannot be evaluated on any public dataset,
because no public IoMT dataset contains device clinical criticality, patient
dependency, or response-impact ground truth. It is therefore evaluated in the
simulation environment against the baseline ladder and ablations defined in
`docs/experiments.md`, measuring unsafe-response rate, unnecessary-isolation
rate, clinical-risk violations and recovery success.

**Honesty requirement:** results from Track B are reported as
simulator-derived throughout, and are never presented as benchmark-dataset
results. The limitation is stated in the paper, not buried
(see `docs/limitations.md`).

---

## 4. Threats to the contribution's validity

Recorded here so they are addressed in the paper rather than discovered in
review.

1. **Simulator realism.** The clinical coupling (e.g. desaturation dynamics)
   is calibrated to published physiological timescales but is not validated
   against real patient data. We claim *relative* behaviour (patient-aware
   selection avoids harmful actions that cyber-only selection takes), never
   absolute clinical accuracy.
2. **Criticality assignment is a parameter, not a finding.** Device
   criticality tiers are configured inputs. The sensitivity analysis
   (`docs/experiments.md`) shows how conclusions vary across plausible
   assignments, rather than asserting one correct assignment.
3. **No comparable prior system.** Track B compares against ablations of our
   own system and against reasonable reconstructions of the detection-only
   and fixed-response strategies described in the reviewed literature. These
   reconstructions are documented and are not claimed to be reimplementations
   of any specific paper.
4. **LLM non-determinism.** The agentic layer defaults to a deterministic
   provider for reproducibility. Results with a real LLM provider are
   reported separately with seeds, model versions and variance across runs.
