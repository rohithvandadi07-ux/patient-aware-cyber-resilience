"""Runtime detection service: loads a trained artifact, scores live feature
vectors, emits `DetectionEvent`s.

Architecture spec Section 10, "Training/runtime split": "the model is trained
offline against dataset files and the trained artifact is loaded at runtime by
the live detection service, which scores the simulator's live event stream."
Section 7, data-flow step 3: "the detection engine scores the event stream; a
feature vector crosses its trained threshold and it emits a `DetectionEvent`."

This module does the loading + scoring + threshold + DetectionEvent-shaping
only. It does not decide *when* to run (that belongs to whatever polls the
simulator's event stream -- Phase 3.5's API wiring, or later a scheduler) and
it does not know about incidents, agents, or risk (Phases 4-5).

Severity mapping: `severity_hint` is a coarse signal for routing (Section 10's
DetectionEvent contract), derived here from (predicted class, confidence) by a
simple documented rule table -- not learned, and not claiming to be a
calibrated risk score (that is the Risk Engine's job in Phase 5, operating on
*clinical* + cyber signal together, per Section 12).
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import joblib
import pandas as pd

from app.cybersecurity.feature_extraction import FeatureWindow, extract_features
from app.cybersecurity.synthetic_data import FEATURE_COLUMNS
from app.schemas.detection import DetectionEvent
from app.schemas.enums import AttackCategory, ImpactLevel

logger = logging.getLogger(__name__)

# Below this confidence, the engine does not emit a DetectionEvent at all --
# Section 10's contract is that every emitted event is "the one piece of
# structured evidence the Investigation Agent is allowed to treat as ground
# truth," so a low-confidence guess must not be emitted as if it were that.
DEFAULT_CONFIDENCE_THRESHOLD = 0.6

# Confidence >= this, for an otherwise-non-benign class, maps to CRITICAL
# severity_hint; otherwise HIGH. Benign ("unknown") predictions never reach
# this function at all -- see `score_window`.
_HIGH_CONFIDENCE_CUTOFF = 0.85

# AttackCategory.UNKNOWN doubles as the synthetic "benign" label (see
# synthetic_data.py's _CLASS_PROFILES comment) -- a prediction of this class
# means "no attack detected," so it must never produce a DetectionEvent.
_BENIGN_LABEL = AttackCategory.UNKNOWN.value


class ModelNotLoadedError(RuntimeError):
    """Raised when scoring is attempted before a model artifact is loaded."""


@dataclass
class LoadedModel:
    estimator: object
    labels: list[str]
    model_name: str
    source_path: Path


def load_model(model_path: Path) -> LoadedModel:
    """Load one `.joblib` artifact produced by `training.save_artifacts`, plus
    its paired metadata JSON for the label list. Raises `FileNotFoundError`
    with a clear message rather than a bare joblib traceback if either file is
    missing -- this runs at service startup, where a confusing stack trace is
    the difference between a 30-second fix and a long debugging session."""
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model artifact not found at {model_path}. Train one first, e.g.:\n"
            "    python -m app.cybersecurity.training"
        )
    metadata_path = model_path.with_suffix("").with_suffix(".metadata.json")
    if not metadata_path.exists():
        raise FileNotFoundError(
            f"Model artifact {model_path} has no paired metadata file at {metadata_path} "
            "-- every artifact from training.save_artifacts is saved with one; this looks "
            "like a hand-placed or corrupted artifact."
        )

    import json

    metadata = json.loads(metadata_path.read_text())
    estimator = joblib.load(model_path)
    return LoadedModel(
        estimator=estimator,
        labels=metadata["labels"],
        model_name=metadata["model_name"],
        source_path=model_path,
    )


class DetectionService:
    """Wraps one loaded model and scores feature windows against it.

    Stateless across calls except for the loaded model itself -- no online
    learning, no mutation of the estimator (architecture spec Section 10:
    "retraining is a deliberate, versioned step, never silent online
    learning").
    """

    def __init__(
        self, model: LoadedModel, confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    ) -> None:
        self._model = model
        self._confidence_threshold = confidence_threshold

    @property
    def model_name(self) -> str:
        return self._model.model_name

    def score_window(self, window: FeatureWindow) -> DetectionEvent | None:
        """Score one device's feature window. Returns `None` -- not a
        low-confidence DetectionEvent -- when the predicted class is benign or
        confidence doesn't clear the threshold, per Section 10's contract that
        every emitted DetectionEvent is trustworthy evidence, not a guess.

        Note: an empty event window is not guaranteed to score as benign --
        the model was trained on CICIoMT2024-shaped flow features where "no
        traffic" is not the same feature vector as "benign traffic," and the
        synthetic benign profile in `synthetic_data.py` has nonzero packet/byte
        rates. Callers should not assume "no events this tick" implies no
        DetectionEvent; it depends on how the model actually scores that
        region of feature space, which this threshold-and-suppress logic is
        here precisely to guard rather than to narrate.
        """
        features = extract_features(window)
        feature_vector = pd.DataFrame([features], columns=FEATURE_COLUMNS)

        predicted_label, confidence = self._predict_with_confidence(feature_vector)

        if predicted_label == _BENIGN_LABEL:
            return None
        if confidence < self._confidence_threshold:
            logger.debug(
                "detection suppressed below confidence threshold: device=%s label=%s confidence=%.3f",
                window.device_id,
                predicted_label,
                confidence,
            )
            return None

        try:
            attack_type = AttackCategory(predicted_label)
        except ValueError:
            logger.warning("model emitted unrecognized label %r; treating as UNKNOWN", predicted_label)
            attack_type = AttackCategory.UNKNOWN

        return DetectionEvent(
            device_id=window.device_id,
            attack_type=attack_type,
            confidence=confidence,
            severity_hint=self._severity_hint(confidence),
            timestamp=window.window_end,
            evidence_ref=self._evidence_ref(window),
        )

    def _predict_with_confidence(self, feature_vector: pd.DataFrame) -> tuple[str, float]:
        if not hasattr(self._model.estimator, "predict_proba"):
            raise ModelNotLoadedError(
                f"Loaded estimator for {self._model.model_name!r} has no predict_proba; "
                "the detection service requires a probabilistic classifier so confidence "
                "is a real measured value, not a fabricated constant."
            )
        probabilities = self._model.estimator.predict_proba(feature_vector)[0]
        class_labels = list(self._model.estimator.classes_)
        best_index = max(range(len(probabilities)), key=lambda i: probabilities[i])
        predicted_class = class_labels[best_index]

        # RandomForestClassifier was trained directly on string labels; XGBoost
        # was trained on integer-encoded labels (see training.py) -- normalize
        # either back to the string label via the metadata's label list.
        if isinstance(predicted_class, str):
            predicted_label = predicted_class
        else:
            predicted_label = self._model.labels[int(predicted_class)]

        return predicted_label, float(probabilities[best_index])

    @staticmethod
    def _severity_hint(confidence: float) -> ImpactLevel:
        return ImpactLevel.CRITICAL if confidence >= _HIGH_CONFIDENCE_CUTOFF else ImpactLevel.HIGH

    @staticmethod
    def _evidence_ref(window: FeatureWindow) -> str:
        """A compact *reference* to the window's evidence, not the evidence
        itself -- `DetectionEvent.evidence_ref`'s contract (schemas/detection.py)
        is explicitly "never the raw evidence itself." A real deployment would
        put this window's event IDs in the time-series store and reference that
        row range; this project has no such store wired up yet (Phase 3 scope
        stops at scoring), so this packs a short, bounded summary instead of
        either fabricating a storage reference or inlining potentially hundreds
        of raw events.
        """
        event_count = len(window.events)
        distinct_types = sorted({e.event_type for e in window.events})
        types_summary = ",".join(distinct_types[:5])
        if len(distinct_types) > 5:
            types_summary += f",+{len(distinct_types) - 5} more"
        return (
            f"window[{window.device_id}]"
            f"[{window.window_start.isoformat()}..{window.window_end.isoformat()}]"
            f"[events={event_count}][types={types_summary or 'none'}]"
            f"[ref={uuid4().hex[:8]}]"
        )
