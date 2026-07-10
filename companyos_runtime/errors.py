"""Typed runtime failures suitable for CLI and API adapters."""


class RuntimeKernelError(Exception):
    """Base class for expected runtime failures."""


class ContractError(RuntimeKernelError):
    """A public runtime object failed strict validation."""


class NotFoundError(RuntimeKernelError):
    """A referenced runtime object does not exist."""


class TransitionError(RuntimeKernelError):
    """A requested state transition is not allowed."""


class LeaseError(RuntimeKernelError):
    """A task lease could not be acquired or used."""


class AuthorizationError(RuntimeKernelError):
    """A capability request was denied."""


class EvidenceError(RuntimeKernelError):
    """Evidence cannot support the requested claim or transition."""


class FreshnessError(RuntimeKernelError):
    """A required runtime surface observation is missing or stale."""


class IntegrityError(RuntimeKernelError):
    """Persisted event or artifact integrity verification failed."""


class SimulatedCrash(RuntimeKernelError):
    """Deterministic fault used by recovery tests and fake workflows."""
