"""Hybrid threat classification with verified TF-IDF model artifacts.

If no artifact is configured the classifier is simply unavailable and scoring uses rules only.
The artifact is a joblib (pickle) file: only load files produced by your own training run.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("ascent.ml")
ML_DECISION_THRESHOLD = 0.5  # Shared with the independent evaluation procedure.


@dataclass
class MlResult:
    probability: float
    model_version: str
    top_terms: list[str]
    model_family: str = "unknown"


class MlClassifier:
    def __init__(self, path: str | None) -> None:
        self._pipeline = None
        self.version: str | None = None
        self.model_family: str | None = None
        if not path:
            return
        try:
            import joblib

            artifact = joblib.load(Path(path))
            self._pipeline = artifact["pipeline"]
            self.version = str(artifact.get("version", "unknown"))
            classifier = self._pipeline.named_steps["clf"]
            self.model_family = str(
                artifact.get("model_family")
                or ("tfidf_mlp" if hasattr(classifier, "coefs_") else "tfidf_logistic_regression")
            )
        except Exception:  # missing/corrupt/incompatible artifact must not take the API down
            log.exception("Could not load ML model from %s; continuing with rules only", path)

    @property
    def available(self) -> bool:
        return self._pipeline is not None

    def predict(self, text: str) -> MlResult | None:
        if not self.available:
            return None
        vec = self._pipeline.named_steps["tfidf"]
        clf = self._pipeline.named_steps["clf"]
        try:
            x = vec.transform([text])
            phishing_idx = list(clf.classes_).index(1)
            probability = float(clf.predict_proba(x)[0][phishing_idx])
            top: list[str] = []
            # Linear models expose signed term weights; MLP feature attributions are not
            # calculated here, so do not present input tokens as model explanations.
            if hasattr(clf, "coef_"):
                contrib = x.multiply(clf.coef_[0]).tocoo()
                names = vec.get_feature_names_out()
                ranked = sorted(zip(contrib.col, contrib.data, strict=True), key=lambda t: -t[1])
                top = [str(names[i]) for i, value in ranked if value > 0][:5]
        except Exception:
            log.exception("Threat classifier inference failed; this request will use rules only")
            self._pipeline = None
            self.model_family = None
            return None
        return MlResult(
            probability=probability,
            model_version=self.version or "unknown",
            top_terms=top,
            model_family=self.model_family or "unknown",
        )
