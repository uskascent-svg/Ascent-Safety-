"""Machine-learning classification (TF-IDF + Logistic Regression), loaded from a trained artifact.

If no artifact is configured the classifier is simply unavailable and scoring uses rules only.
The artifact is a joblib (pickle) file: only load files produced by your own training run.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("ascent.ml")


@dataclass
class MlResult:
    probability: float
    model_version: str
    top_terms: list[str]


class MlClassifier:
    def __init__(self, path: str | None) -> None:
        self._pipeline = None
        self.version: str | None = None
        if not path:
            return
        try:
            import joblib

            artifact = joblib.load(Path(path))
            self._pipeline = artifact["pipeline"]
            self.version = str(artifact.get("version", "unknown"))
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
        x = vec.transform([text])
        phishing_idx = list(clf.classes_).index(1)
        probability = float(clf.predict_proba(x)[0][phishing_idx])
        # Explainability: terms in this message that pushed the score toward "phishing".
        contrib = x.multiply(clf.coef_[0]).tocoo()
        names = vec.get_feature_names_out()
        ranked = sorted(zip(contrib.col, contrib.data, strict=True), key=lambda t: -t[1])
        top = [str(names[i]) for i, v in ranked if v > 0][:5]
        return MlResult(
            probability=probability, model_version=self.version or "unknown", top_terms=top
        )
