from services.legacy.models import SoftwareFingerprint


class EOLLookup:
    """Queries vendor-support information using static fallback rules."""

    STATIC_EOL_PRODUCTS = {
        ("microsoft", "windows 7"),
        ("microsoft", "windows server 2008"),
        ("canonical", "ubuntu 18.04"),
        ("apache", "struts 2.3"),
        ("php", "php 5"),
        ("oracle", "java 7"),
    }

    def lookup_vendor_support(self, fingerprint: SoftwareFingerprint) -> dict[str, object]:
        """Return support state for a software fingerprint.

        Args:
            fingerprint: Normalized software identity.

        Returns:
            Support metadata with status flags.
        """

        product_key = fingerprint.product
        if fingerprint.version and not any(char.isdigit() for char in fingerprint.product):
            product_key = f"{fingerprint.product} {fingerprint.version.split('.')[0]}"
        eol = (fingerprint.vendor, product_key) in self.STATIC_EOL_PRODUCTS
        unsupported = eol or fingerprint.vendor == "unknown" or fingerprint.product == "unknown"
        return {
            "unsupported": unsupported,
            "eol": eol,
            "support_status": "eol" if eol else "unknown" if unsupported else "supported",
        }
