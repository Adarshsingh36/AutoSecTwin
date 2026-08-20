class CategoricalEncoder:
    """Encodes categorical vulnerability and service values into stable floats."""

    SEVERITY = {"UNKNOWN": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}

    def encode_severity(self, severity: str | None) -> float:
        """Encode severity text to a bounded numeric value."""

        return self.SEVERITY.get((severity or "UNKNOWN").upper(), 0.0)

    def encode_bool(self, value: bool | None) -> float:
        """Encode boolean-like values for ML features."""

        return 1.0 if value else 0.0
