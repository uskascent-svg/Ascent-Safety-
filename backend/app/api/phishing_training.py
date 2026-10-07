import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.database.session import get_db
from app.models import RoleName, TrainingAttempt, TrainingScenario, User
from app.schemas.training import (
    TrainingAttemptCreate,
    TrainingAttemptOut,
    TrainingProgress,
    TrainingScenarioAdmin,
    TrainingScenarioCreate,
    TrainingScenarioPage,
    TrainingScenarioPlay,
)
from app.security.deps import get_current_user, require_roles
from app.services import audit

router = APIRouter(prefix="/api/phishing-training", tags=["phishing-training"])
admin_only = require_roles(RoleName.ADMINISTRATOR)


def _play(scenario: TrainingScenario) -> TrainingScenarioPlay:
    return TrainingScenarioPlay.model_validate(scenario, from_attributes=True)


@router.get("/scenarios", response_model=TrainingScenarioPage)
def list_training_scenarios(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = db.scalars(
        select(TrainingScenario)
        .where(TrainingScenario.is_active.is_(True))
        .order_by(TrainingScenario.category, TrainingScenario.title)
    ).all()
    return TrainingScenarioPage(items=[_play(row) for row in rows], total=len(rows))


@router.post("/attempts", response_model=TrainingAttemptOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
def submit_training_attempt(
    request: Request,
    payload: TrainingAttemptCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scenario = db.get(TrainingScenario, payload.scenario_id)
    if scenario is None or not scenario.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Training scenario not found")

    expected = {item["id"] for item in scenario.indicators}
    selected = set(payload.discovered_indicators)
    found_ids = expected & selected
    missed_ids = expected - selected
    decision_correct = payload.decision == scenario.correct_decision
    recall = len(found_ids) / len(expected) if expected else 1.0
    precision = len(found_ids) / len(selected) if selected else (1.0 if not expected else 0.0)
    indicator_score = recall * 65 + precision * 35
    correct_actions = set(scenario.correct_actions)
    chosen_actions = set(payload.response_actions)
    action_score = (
        len(correct_actions & chosen_actions) / len(correct_actions) if correct_actions else 1.0
    )
    speed_bonus = 5 if payload.elapsed_seconds <= 90 else 3 if payload.elapsed_seconds <= 300 else 0
    score = round(
        min(
            100,
            (40 if decision_correct else 0)
            + indicator_score * 0.45
            + action_score * 10
            + speed_bonus,
        )
    )
    accuracy = round(recall * 100, 1)

    attempt = TrainingAttempt(
        user_id=user.id,
        scenario_id=scenario.id,
        decision=payload.decision,
        discovered_indicators=sorted(selected),
        response_actions=sorted(chosen_actions),
        elapsed_seconds=payload.elapsed_seconds,
        security_score=score,
        detection_accuracy=accuracy,
        indicator_score=round(indicator_score, 1),
        action_score=round(action_score * 100, 1),
        indicators_missed=sorted(missed_ids),
    )
    db.add(attempt)
    db.flush()
    audit.record(
        db,
        "phishing_training.attempt",
        request,
        user.id,
        {"attempt_id": str(attempt.id), "scenario_id": str(scenario.id), "score": score},
    )
    db.commit()
    db.refresh(attempt)

    indicator_map = {item["id"]: item for item in scenario.indicators}
    found = [indicator_map[key] for key in sorted(found_ids)]
    missed = [indicator_map[key] for key in sorted(missed_ids)]
    actions = sorted(correct_actions | chosen_actions)
    feedback = [
        {
            "id": action,
            "label": action.replace("_", " ").title(),
            "correct": action in correct_actions,
            "selected": action in chosen_actions,
            "rationale": scenario.action_rationales.get(
                action, "Use your organization's approved response process."
            ),
        }
        for action in actions
    ]
    if not decision_correct:
        improvement = (
            "Pause before deciding; compare the sender, destination, and requested action "
            "against a trusted channel."
        )
    elif missed:
        improvement = (
            "Inspect every sender, reply-to, destination, attachment, and pressure cue "
            "before you decide."
        )
    elif action_score < 1:
        improvement = "Practice the response steps as well as identifying the suspicious message."
    else:
        improvement = (
            "Strong investigation. Keep verifying unusual requests through a known, independent "
            "channel."
        )
    return TrainingAttemptOut(
        id=attempt.id,
        scenario_id=scenario.id,
        security_score=score,
        detection_accuracy=accuracy,
        indicator_score=attempt.indicator_score,
        action_score=attempt.action_score,
        indicators_found=found,
        indicators_missed=missed,
        actions_feedback=feedback,
        decision_correct=decision_correct,
        attack_technique=scenario.attack_technique,
        explanation=scenario.explanation,
        prevention=scenario.prevention,
        recommended_improvement=improvement,
        created_at=attempt.created_at,
    )


@router.get("/progress", response_model=TrainingProgress)
def training_progress(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    attempts = db.scalars(
        select(TrainingAttempt)
        .where(TrainingAttempt.user_id == user.id)
        .order_by(TrainingAttempt.created_at.desc())
    ).all()
    total_scenarios = (
        db.scalar(
            select(func.count(TrainingScenario.id)).where(TrainingScenario.is_active.is_(True))
        )
        or 0
    )
    if not attempts:
        recommended = db.scalar(
            select(TrainingScenario)
            .where(TrainingScenario.is_active.is_(True))
            .order_by(TrainingScenario.category)
        )
        return TrainingProgress(
            scenarios_completed=0,
            average_score=0,
            detection_accuracy=0,
            training_level="Foundation",
            weakest_category=None,
            current_streak=0,
            badges=[],
            certificate_eligible=False,
            recommended_next=_play(recommended) if recommended else None,
        )

    scores_by_category: dict[str, list[int]] = defaultdict(list)
    for attempt in attempts:
        scores_by_category[attempt.scenario.category].append(attempt.security_score)
    weakest = min(
        scores_by_category,
        key=lambda key: sum(scores_by_category[key]) / len(scores_by_category[key]),
    )
    days = {attempt.created_at.date() for attempt in attempts if attempt.created_at}
    streak = 0
    day = datetime.now(UTC).date()
    if day not in days:
        day -= timedelta(days=1)
    while day in days:
        streak += 1
        day -= timedelta(days=1)

    attempted_ids = {attempt.scenario_id for attempt in attempts}
    recommended = (
        db.scalar(
            select(TrainingScenario)
            .where(TrainingScenario.is_active.is_(True), TrainingScenario.id.not_in(attempted_ids))
            .order_by(TrainingScenario.category)
        )
        if len(attempted_ids) < total_scenarios
        else db.scalar(
            select(TrainingScenario).where(
                TrainingScenario.is_active.is_(True), TrainingScenario.category == weakest
            )
        )
    )
    average = sum(attempt.security_score for attempt in attempts) / len(attempts)
    accuracy = sum(attempt.detection_accuracy for attempt in attempts) / len(attempts)
    badges = []
    if len(attempts) >= 1:
        badges.append("First investigation")
    if accuracy >= 80 and len(attempts) >= 3:
        badges.append("Signal finder")
    if streak >= 3:
        badges.append("Three-day practice streak")
    level = (
        "Advanced"
        if average >= 85 and len(attempts) >= 8
        else "Practiced"
        if len(attempts) >= 3
        else "Foundation"
    )
    return TrainingProgress(
        scenarios_completed=len(attempts),
        average_score=round(average, 1),
        detection_accuracy=round(accuracy, 1),
        training_level=level,
        weakest_category=weakest,
        current_streak=streak,
        badges=badges,
        certificate_eligible=len(attempts) >= min(total_scenarios, 10) and average >= 80,
        recommended_next=_play(recommended) if recommended else None,
    )


@router.get("/admin/scenarios", response_model=list[TrainingScenarioAdmin])
def list_scenarios_admin(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(admin_only),
):
    query = select(TrainingScenario)
    if not include_inactive:
        query = query.where(TrainingScenario.is_active.is_(True))
    return db.scalars(query.order_by(TrainingScenario.category, TrainingScenario.title)).all()


@router.post("/admin/scenarios", response_model=TrainingScenarioAdmin, status_code=201)
def create_scenario(
    request: Request,
    payload: TrainingScenarioCreate,
    db: Session = Depends(get_db),
    user: User = Depends(admin_only),
):
    if db.scalar(select(TrainingScenario.id).where(TrainingScenario.slug == payload.slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Scenario slug already exists")
    scenario = TrainingScenario(
        **payload.model_dump(exclude={"indicators"}),
        indicators=[item.model_dump() for item in payload.indicators],
        created_by=user.id,
    )
    db.add(scenario)
    db.flush()
    audit.record(
        db, "phishing_training.scenario_create", request, user.id, {"scenario_id": str(scenario.id)}
    )
    db.commit()
    db.refresh(scenario)
    return scenario


@router.put("/admin/scenarios/{scenario_id}", response_model=TrainingScenarioAdmin)
def replace_scenario(
    request: Request,
    scenario_id: uuid.UUID,
    payload: TrainingScenarioCreate,
    db: Session = Depends(get_db),
    user: User = Depends(admin_only),
):
    scenario = db.get(TrainingScenario, scenario_id)
    if scenario is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
    duplicate = db.scalar(
        select(TrainingScenario.id).where(
            TrainingScenario.slug == payload.slug, TrainingScenario.id != scenario_id
        )
    )
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scenario slug already exists")
    for key, value in payload.model_dump().items():
        setattr(scenario, key, value)
    audit.record(
        db, "phishing_training.scenario_update", request, user.id, {"scenario_id": str(scenario.id)}
    )
    db.commit()
    db.refresh(scenario)
    return scenario
