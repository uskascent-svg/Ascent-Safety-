"""Train and evaluate the phishing text classifier (TF-IDF -> Logistic Regression).

Usage:
    python -m ml.training.train --dataset ml/datasets/emails.csv \
        --text-col body --subject-col subject --label-col label \
        --out ml/models/phishing_tfidf_lr.joblib --metrics ml/evaluation/metrics.json

All reported metrics are computed on a held-out, stratified test split of YOUR dataset. This script
ships no data and no pre-computed results.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


def build_text(subject: str, body: str) -> str:
    """Must match app.detection.phishing.text.model_text so training and inference agree."""
    return f"{subject}\n{body}"[:20_000]


def train(
    dataset: Path,
    text_col: str,
    label_col: str,
    out_model: Path,
    out_metrics: Path,
    subject_col: str | None = None,
    positive_label: str = "1",
    test_size: float = 0.2,
    seed: int = 42,
    min_df: int = 2,
) -> dict:
    df = pd.read_csv(dataset).dropna(subset=[text_col, label_col])
    subjects = df[subject_col].fillna("").astype(str) if subject_col else [""] * len(df)
    texts = [build_text(s, b) for s, b in zip(subjects, df[text_col].astype(str))]
    labels = (df[label_col].astype(str) == str(positive_label)).astype(int).to_numpy()

    if len(set(labels)) < 2:
        raise ValueError("Dataset needs both phishing and non-phishing examples")

    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=seed, stratify=labels
    )
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=min_df,
                                      sublinear_tf=True, max_features=50_000)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )
    pipeline.fit(x_train, y_train)

    predicted = pipeline.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predicted, average="binary", pos_label=1, zero_division=0
    )
    trained_at = datetime.now(timezone.utc).isoformat()
    metrics = {
        "model": "tfidf+logistic_regression",
        "trained_at": trained_at,
        "sklearn_version": sklearn.__version__,
        "dataset": str(dataset),
        "rows_total": len(texts),
        "rows_train": len(x_train),
        "rows_test": len(x_test),
        "test_size": test_size,
        "seed": seed,
        "positive_class_rows": int(labels.sum()),
        "accuracy": float(accuracy_score(y_test, predicted)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        # rows = actual [non-phishing, phishing]; columns = predicted [non-phishing, phishing]
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=[0, 1]).tolist(),
    }

    out_model.parent.mkdir(parents=True, exist_ok=True)
    out_metrics.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "version": f"tfidf-lr-{trained_at[:10]}"}, out_model)
    out_metrics.write_text(json.dumps(metrics, indent=2))
    return metrics


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, required=True)
    p.add_argument("--text-col", required=True)
    p.add_argument("--label-col", required=True)
    p.add_argument("--subject-col")
    p.add_argument("--positive-label", default="1", help="label value that means phishing")
    p.add_argument("--out", type=Path, default=Path("ml/models/phishing_tfidf_lr.joblib"))
    p.add_argument("--metrics", type=Path, default=Path("ml/evaluation/metrics.json"))
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=42)
    a = p.parse_args()
    m = train(a.dataset, a.text_col, a.label_col, a.out, a.metrics, a.subject_col,
              a.positive_label, a.test_size, a.seed)
    print(json.dumps(m, indent=2))


if __name__ == "__main__":
    main()
