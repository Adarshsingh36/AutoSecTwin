class FeaturePreprocessor:
    """Normalizes numeric features and handles missing values."""

    def normalize(self, value: float | int | None, maximum: float = 1.0) -> float:
        """Normalize a numeric value into the 0.0 to 1.0 range."""

        if value is None:
            return 0.0
        if maximum <= 0:
            maximum = 1.0
        return max(0.0, min(1.0, float(value) / maximum))

    def fill_missing(self, value: float | None, default: float = 0.0) -> float:
        """Replace missing feature values with a deterministic default."""

        return default if value is None else value
