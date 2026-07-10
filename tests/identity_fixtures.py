"""Lazy authenticated principals shared by runtime-kernel tests.

The real identity boundary deliberately uses production-strength PBKDF2.  Test
cases therefore create one fixture per database and reuse each issued session
throughout the case instead of authenticating again for every assertion.
"""

from __future__ import annotations

from collections.abc import Iterable

from companyos_runtime.identity import IdentityManager, Role, VerifiedPrincipal
from companyos_runtime.store import SQLiteStore


class IdentityFixture:
    """Create role-scoped test principals on demand.

    The bootstrap principal explicitly holds the control-plane roles used by
    the owner/system/release/observer paths.  Worker and evaluator sessions are
    always distinct principals so maker/checker assertions remain meaningful.
    """

    def __init__(self, store: SQLiteStore):
        self.manager = IdentityManager(store)
        self._owner = self.manager.bootstrap_owner(
            display_name="test-control",
            credential="companyos-test-control-credential-v1",
        )
        self.manager.set_roles(
            self._owner,
            display_name="test-control",
            roles={Role.OWNER, Role.SYSTEM, Role.RELEASE, Role.OBSERVER},
        )
        self._sessions: dict[tuple[str, tuple[Role, ...]], VerifiedPrincipal] = {}

    @property
    def owner(self) -> VerifiedPrincipal:
        return self._owner

    @property
    def system(self) -> VerifiedPrincipal:
        return self._owner

    @property
    def release(self) -> VerifiedPrincipal:
        return self._owner

    @property
    def observer(self) -> VerifiedPrincipal:
        return self._owner

    @property
    def worker(self) -> VerifiedPrincipal:
        return self.session("worker", Role.WORKER)

    @property
    def evaluator(self) -> VerifiedPrincipal:
        return self.session("evaluator", Role.EVALUATOR)

    @property
    def provider_attestor(self) -> VerifiedPrincipal:
        return self.session("provider-attestor", Role.PROVIDER_ATTESTOR)

    @property
    def human_acceptor(self) -> VerifiedPrincipal:
        return self.session("human-acceptor", Role.HUMAN_ACCEPTOR)

    @property
    def business_reviewer(self) -> VerifiedPrincipal:
        return self.session("business-reviewer", Role.BUSINESS_REVIEWER)

    def worker_named(self, name: str) -> VerifiedPrincipal:
        return self.session(name, Role.WORKER)

    def session(
        self, name: str, *roles: Role | str | Iterable[Role | str]
    ) -> VerifiedPrincipal:
        flattened: list[Role | str] = []
        for role in roles:
            if isinstance(role, (Role, str)):
                flattened.append(role)
            else:
                flattened.extend(role)
        normalized = tuple(
            sorted(
                {item if isinstance(item, Role) else Role(item) for item in flattened},
                key=lambda item: item.value,
            )
        )
        if not normalized:
            raise ValueError("at least one role is required")
        key = (name, normalized)
        cached = self._sessions.get(key)
        if cached is not None:
            return cached
        credential = f"companyos-test-{name}-credential-v1"
        self.manager.create_principal(
            self._owner,
            display_name=f"test-{name}",
            credential=credential,
            roles=set(normalized),
        )
        issued = self.manager.authenticate(
            display_name=f"test-{name}", credential=credential
        )
        self._sessions[key] = issued
        return issued
