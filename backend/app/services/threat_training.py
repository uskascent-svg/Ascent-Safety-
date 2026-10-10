"""Controlled feedback training; only signed, independently evaluated artifacts are loadable."""

import hashlib
import hmac
import json
import os
import tempfile
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import joblib
from cryptography.fernet import Fernet, InvalidToken
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from app.core.config import get_settings
from app.database.session import SessionLocal
from app.models import ThreatFeedback, ThreatModelVersion, ThreatTrainingJob

MIN_SAMPLES = 20
MIN_PER_CLASS = 10
MIN_TRAIN_PER_CLASS = 3
MAX_TEST_BYTES = 50 * 1024 * 1024


class TrainingUnavailable(RuntimeError):
    pass


def encrypt_sample(text: str) -> str:
    key = get_settings().threat_analysis_data_key
    if not key:
        raise TrainingUnavailable("Encrypted training storage is not configured")
    try:
        return Fernet(key.encode()).encrypt(text.encode()).decode()
    except (ValueError, TypeError):
        raise TrainingUnavailable("Training data encryption key is invalid") from None


def _decrypt_sample(ciphertext: str) -> str:
    key = get_settings().threat_analysis_data_key
    if not key:
        raise TrainingUnavailable("Encrypted training storage is not configured")
    try:
        return Fernet(key.encode()).decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        raise TrainingUnavailable("An approved training sample cannot be decrypted") from None


def _evaluation_set() -> tuple[list[str], list[int]]:
    configured = get_settings().threat_analysis_independent_test_set
    if not configured:
        raise TrainingUnavailable("An independent labeled evaluation set is not configured")
    path = Path(configured).resolve()
    if not path.is_file() or path.stat().st_size > MAX_TEST_BYTES:
        raise TrainingUnavailable("The independent evaluation set is unavailable or too large")
    texts: list[str] = []
    labels: list[int] = []
    seen: set[str] = set()
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if len(texts) >= 10_000:
                    raise TrainingUnavailable("The evaluation set exceeds 10,000 records")
                row = json.loads(line)
                text, label = row.get("text"), row.get("label")
                if not isinstance(text, str) or label not in {"benign", "malicious"}:
                    raise TrainingUnavailable(
                        "Evaluation records need text and benign/malicious labels"
                    )
                normalized = " ".join(text.lower().split())
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                texts.append(text)
                labels.append(int(label == "malicious"))
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError, TypeError):
        raise TrainingUnavailable("The independent evaluation set is malformed") from None
    counts = Counter(labels)
    if len(texts) < MIN_SAMPLES or min(counts.get(0, 0), counts.get(1, 0)) < MIN_PER_CLASS:
        raise TrainingUnavailable(
            "Evaluation set needs at least 20 unique records and 10 per class"
        )
    return texts, labels


def _evaluate(pipeline: Pipeline, texts: list[str], labels: list[int]) -> dict[str, float | int]:
    probabilities = pipeline.predict_proba(texts)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    negatives = sum(label == 0 for label in labels)
    positives = sum(label == 1 for label in labels)
    false_positive = sum(
        pred == 1 and label == 0 for pred, label in zip(predictions, labels, strict=True)
    )
    false_negative = sum(
        pred == 0 and label == 1 for pred, label in zip(predictions, labels, strict=True)
    )
    return {
        "sample_count": len(labels),
        "benign_count": negatives,
        "malicious_count": positives,
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": false_positive / negatives if negatives else 1.0,
        "false_negative_rate": false_negative / positives if positives else 1.0,
    }


def _passes(metrics: dict[str, float | int]) -> bool:
    return (
        metrics["f1"] >= 0.65
        and metrics["precision"] >= 0.60
        and metrics["recall"] >= 0.60
        and metrics["false_positive_rate"] <= 0.10
        and metrics["false_negative_rate"] <= 0.40
    )


def _signature(version: str, digest: str) -> str:
    key = get_settings().threat_analysis_model_hmac_key
    if not key or len(key.encode()) < 32:
        raise TrainingUnavailable("A model signing key of at least 32 characters is required")
    return hmac.new(key.encode(), f"{version}:{digest}".encode(), hashlib.sha256).hexdigest()


def _verified_path(row: ThreatModelVersion) -> Path:
    path = Path(row.artifact_path).resolve()
    root = Path(get_settings().threat_analysis_model_dir).resolve()
    if root not in path.parents or not path.is_file():
        raise TrainingUnavailable("Model artifact path is invalid")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = _signature(row.version, digest)
    if not hmac.compare_digest(digest, row.sha256) or not hmac.compare_digest(
        expected, row.signature
    ):
        raise TrainingUnavailable("Model artifact signature verification failed")
    return path


def _pipeline_compatible(pipeline) -> bool:
    return (
        isinstance(pipeline, Pipeline)
        and [name for name, _ in pipeline.steps] == ["tfidf", "clf"]
        and hasattr(pipeline.named_steps["tfidf"], "transform")
        and hasattr(pipeline.named_steps["clf"], "predict_proba")
        and set(pipeline.named_steps["clf"].classes_) == {0, 1}
    )


def run_training_job(job_id: uuid.UUID) -> None:
    with SessionLocal() as db:
        job = db.get(ThreatTrainingJob, job_id)
        if job is None or job.status != "queued":
            return
        job.status = "running"
        job.message = "Training and evaluating candidate model."
        db.commit()
    try:
        test_texts, test_labels = _evaluation_set()
        test_hashes = {
            hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
            for text in test_texts
        }
        with SessionLocal() as db:
            training_job = db.get(ThreatTrainingJob, job_id)
            if training_job is None:
                raise TrainingUnavailable("Training job record disappeared")
            feedback = (
                db.query(ThreatFeedback)
                .filter(
                    ThreatFeedback.status == "approved",
                    ThreatFeedback.training_sample_encrypted.is_not(None),
                )
                .all()
            )
            samples = []
            shares = Counter()
            seen: dict[str, str] = {}
            conflicted: set[str] = set()
            for item in feedback:
                text = _decrypt_sample(item.training_sample_encrypted)
                label = item.candidate_label
                digest = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
                if digest in test_hashes:
                    continue
                if digest in conflicted:
                    continue
                if digest in seen:
                    if seen[digest] != label:
                        samples = [sample for sample in samples if sample[2] != digest]
                        seen.pop(digest, None)
                        conflicted.add(digest)
                    continue
                seen[digest] = label
                samples.append((text, int(label == "malicious"), digest))
                shares[item.user_id] += 1
            counts = Counter(label for _, label, _ in samples)
            if min(counts.get(0, 0), counts.get(1, 0)) < MIN_TRAIN_PER_CLASS:
                raise TrainingUnavailable(
                    "Need at least three independent approved samples per class"
                )
            if max(shares.values(), default=0) / len(samples) > 0.8:
                raise TrainingUnavailable("One submitter contributes too much training data")
            train_texts = [row[0] for row in samples]
            train_labels = [row[1] for row in samples]
            training_job.sample_count = len(samples)
            db.commit()

        pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(ngram_range=(1, 2), max_features=150_000, sublinear_tf=True),
                ),
                (
                    "clf",
                    LogisticRegression(max_iter=1000, class_weight="balanced", random_state=17),
                ),
            ]
        )
        pipeline.fit(train_texts, train_labels)
        metrics = _evaluate(pipeline, test_texts, test_labels)
        if not _passes(metrics):
            raise TrainingUnavailable("Candidate did not meet the independent evaluation gates")

        version = f"threat-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        settings = get_settings()
        root = Path(settings.threat_analysis_model_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        artifact = root / f"{version}.joblib"
        with tempfile.NamedTemporaryFile(
            dir=root, prefix="candidate-", suffix=".tmp", delete=False
        ) as tmp:
            temp_path = Path(tmp.name)
        try:
            joblib.dump({"pipeline": pipeline, "version": version}, temp_path)
            os.replace(temp_path, artifact)
        finally:
            temp_path.unlink(missing_ok=True)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        signature = _signature(version, digest)
        with SessionLocal() as db:
            job = db.get(ThreatTrainingJob, job_id)
            model = ThreatModelVersion(
                version=version,
                state="candidate",
                artifact_path=str(artifact),
                sha256=digest,
                signature=signature,
                metrics=metrics,
                created_by_id=job.requested_by_id,
            )
            db.add(model)
            db.flush()
            job.model_version_id = model.id
            job.status = "candidate"
            job.message = (
                "Candidate passed the independent evaluation gates; administrator "
                "promotion is required."
            )
            job.metrics = metrics
            job.finished_at = datetime.now(UTC)
            db.commit()
    except Exception as exc:
        with SessionLocal() as db:
            job = db.get(ThreatTrainingJob, job_id)
            if job:
                job.status = "rejected" if isinstance(exc, TrainingUnavailable) else "failed"
                job.message = (
                    str(exc)[:500]
                    if isinstance(exc, TrainingUnavailable)
                    else "Training failed; inspect server logs."
                )
                job.finished_at = datetime.now(UTC)
                db.commit()


def evaluate_for_promotion(row: ThreatModelVersion) -> dict[str, float | int]:
    path = _verified_path(row)
    pipeline = joblib.load(path)
    if (
        not isinstance(pipeline, dict)
        or pipeline.get("version") != row.version
        or not _pipeline_compatible(pipeline.get("pipeline"))
    ):
        raise TrainingUnavailable("Signed model artifact has an incompatible pipeline")
    texts, labels = _evaluation_set()
    metrics = _evaluate(pipeline["pipeline"], texts, labels)
    if not _passes(metrics):
        raise TrainingUnavailable("Candidate no longer passes promotion thresholds")
    with SessionLocal() as db:
        active = db.query(ThreatModelVersion).filter_by(state="active").one_or_none()
        if active is not None and active.id != row.id:
            active_path = _verified_path(active)
            active_bundle = joblib.load(active_path)
            if not isinstance(active_bundle, dict) or not _pipeline_compatible(
                active_bundle.get("pipeline")
            ):
                raise TrainingUnavailable("The active model artifact is incompatible")
            active_metrics = _evaluate(active_bundle["pipeline"], texts, labels)
            metrics["active_f1"] = active_metrics["f1"]
            metrics["active_false_positive_rate"] = active_metrics["false_positive_rate"]
            if metrics["f1"] + 0.02 < active_metrics["f1"]:
                raise TrainingUnavailable("Candidate fails the active-model non-regression gate")
    return metrics


def verified_active_model_path() -> tuple[str, str] | None:
    try:
        with SessionLocal() as db:
            row = db.query(ThreatModelVersion).filter_by(state="active").one_or_none()
            return (str(_verified_path(row)), str(row.id)) if row else None
    except Exception:
        return None
