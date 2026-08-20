from collections.abc import Iterable

import optuna
from sklearn.isotonic import IsotonicRegression

from services.confidence.fusion import ConfidenceFusionEngine, FusionInputs


class ConfidenceWeightOptimizer:
    """Optimizes fusion weights with Optuna and calibrates scores isotonicly."""

    def __init__(self) -> None:
        self.fusion = ConfidenceFusionEngine()
        self.calibrator = IsotonicRegression(out_of_bounds="clip")

    def optimize(self, rows: Iterable[tuple[FusionInputs, float]], trials: int = 50) -> dict[str, float]:
        """Return weights minimizing squared error against validation labels."""

        dataset = list(rows)
        if not dataset:
            return self.fusion.DEFAULT_WEIGHTS.copy()

        def objective(trial: optuna.Trial) -> float:
            weights = {
                key: trial.suggest_float(key, 0.0, 1.0)
                for key in self.fusion.DEFAULT_WEIGHTS
            }
            error = 0.0
            for inputs, label in dataset:
                score, _ = self.fusion.fuse(inputs, weights)
                error += (score - label) ** 2
            return error / len(dataset)

        study = optuna.create_study(direction="minimize")
        study.optimize(objective, n_trials=trials, show_progress_bar=False)
        return self.fusion.normalize_weights(study.best_params)

    def calibrate(self, scores: list[float], labels: list[float]) -> IsotonicRegression:
        """Fit isotonic regression calibration for confidence scores."""

        self.calibrator.fit(scores, labels)
        return self.calibrator
