"""Custom exceptions for cp-review."""


class CpReviewError(Exception):
    """Base exception for application-level errors."""


class ConfigurationError(CpReviewError):
    """Raised when configuration cannot be loaded or validated."""


class CheckPointApiError(CpReviewError):
    """Raised when the Check Point Management API returns an error."""


class ReadOnlyViolationError(CpReviewError):
    """Raised when a mutating API command is attempted."""


class CollectionError(CpReviewError):
    """Raised when data collection cannot continue safely."""
