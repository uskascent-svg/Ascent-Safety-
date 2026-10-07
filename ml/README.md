# Machine learning (phishing text classifier)

Initial model: **TF-IDF → Logistic Regression**. Later experiments (Random Forest, Naive Bayes, SVM)
can be added under `training/` and compared with the same metrics.

## Data
No datasets are included. Use a legitimate, labelled email corpus (e.g. a public phishing corpus plus
a public ham corpus) and review its licence. Place the CSV in `ml/datasets/` (git-ignored).

Required columns: body text, a label, and optionally a subject. The classifier is trained on
`subject + "\n" + body` — the same text the API builds at inference time.

## Train
```
pip install -r ml/requirements.txt
python -m ml.training.train --dataset ml/datasets/emails.csv \
    --text-col body --subject-col subject --label-col label --positive-label 1
```
Outputs `ml/models/phishing_tfidf_lr.joblib` and `ml/evaluation/metrics.json`
(accuracy, precision, recall, F1, confusion matrix on a held-out stratified split).
Report these numbers as-is; never quote metrics from a different dataset.

## Enable in the API
Set `ML_MODEL_PATH=ml/models/phishing_tfidf_lr.joblib`. Without it the API uses rules only and
reports `ml.available = false`. The artifact is a pickle: only load files you trained yourself.
ML contributes 30% of the score and can never classify a message as phishing on its own — at least
two rule indicators are required.
