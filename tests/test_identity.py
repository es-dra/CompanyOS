from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from companyos_runtime.errors import AuthorizationError
from companyos_runtime.identity import (
    MAX_SESSION_TTL_SECONDS,
    IdentityManager,
    Role,
    VerifiedPrincipal,
)
from companyos_runtime.store import SQLiteStore


class IdentityManagerTests(unittest.TestCase):
    OWNER_CREDENTIAL = "owner-credential-strong"
    WORKER_CREDENTIAL = "worker-credential-strong"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "runtime.db"
        self.store = SQLiteStore(self.database)
        self.store.initialize()
        self.identities = IdentityManager(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _bootstrap(self) -> VerifiedPrincipal:
        return self.identities.bootstrap_owner(
            display_name="Owner One",
            credential=self.OWNER_CREDENTIAL,
        )

    def _create_worker(self, owner: VerifiedPrincipal) -> None:
        self.identities.create_principal(
            owner,
            display_name="Worker One",
            credential=self.WORKER_CREDENTIAL,
            roles={Role.WORKER, Role.OBSERVER},
        )

    def test_tofu_bootstrap_persists_only_derived_secrets(self) -> None:
        owner = self._bootstrap()
        principal = self.identities.require_role(owner, Role.OWNER)
        self.assertEqual(principal.display_name, "Owner One")
        self.assertEqual(principal.roles, frozenset({Role.OWNER}))

        rows = self.store.query("SELECT * FROM principals")
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(bytes(rows[0]["credential_salt"])), 16)
        self.assertEqual(len(bytes(rows[0]["credential_hash"])), 32)
        self.assertNotEqual(
            bytes(rows[0]["credential_hash"]), self.OWNER_CREDENTIAL.encode()
        )
        session = self.store.query("SELECT * FROM authenticated_sessions")[0]
        self.assertEqual(len(bytes(session["session_token_hash"])), 32)
        self.assertEqual(self.store.query("SELECT * FROM events"), [])

        for path in (self.database, Path(f"{self.database}-wal")):
            if path.exists():
                self.assertNotIn(self.OWNER_CREDENTIAL.encode(), path.read_bytes())

    def test_duplicate_bootstrap_is_denied_even_after_owner_exists(self) -> None:
        self._bootstrap()
        with self.assertRaisesRegex(AuthorizationError, "bootstrap is closed"):
            self.identities.bootstrap_owner(
                display_name="Second Owner",
                credential="different-owner-credential",
            )
        self.assertEqual(len(self.store.query("SELECT * FROM principals")), 1)

    def test_wrong_credential_unknown_principal_and_role_shortfall_fail_closed(
        self,
    ) -> None:
        owner = self._bootstrap()
        self._create_worker(owner)

        with self.assertRaisesRegex(
            AuthorizationError, "invalid principal or credential"
        ):
            self.identities.authenticate(
                display_name="Worker One", credential="wrong-credential-value"
            )
        with self.assertRaisesRegex(
            AuthorizationError, "invalid principal or credential"
        ):
            self.identities.authenticate(
                display_name="Unknown", credential="wrong-credential-value"
            )

        worker = self.identities.authenticate(
            display_name="worker one", credential=self.WORKER_CREDENTIAL
        )
        self.assertIn(
            Role.WORKER, self.identities.require_role(worker, Role.WORKER).roles
        )
        with self.assertRaisesRegex(AuthorizationError, "required role is missing"):
            self.identities.require_role(worker, Role.EVALUATOR)
        with self.assertRaisesRegex(AuthorizationError, "required role is missing"):
            self.identities.require_role(owner, Role.HUMAN_ACCEPTOR)

    def test_disable_revokes_sessions_and_reenable_does_not_restore_them(self) -> None:
        owner = self._bootstrap()
        self._create_worker(owner)
        worker = self.identities.authenticate(
            display_name="Worker One", credential=self.WORKER_CREDENTIAL
        )

        disabled = self.identities.disable_principal(owner, display_name="Worker One")
        self.assertFalse(disabled.enabled)
        with self.assertRaises(AuthorizationError):
            self.identities.require_role(worker, Role.WORKER)
        with self.assertRaises(AuthorizationError):
            self.identities.authenticate(
                display_name="Worker One", credential=self.WORKER_CREDENTIAL
            )

        enabled = self.identities.enable_principal(owner, display_name="Worker One")
        self.assertTrue(enabled.enabled)
        with self.assertRaises(AuthorizationError):
            self.identities.require_role(worker, Role.WORKER)
        replacement = self.identities.authenticate(
            display_name="Worker One", credential=self.WORKER_CREDENTIAL
        )
        self.identities.require_role(replacement, Role.WORKER)

    def test_rotation_requires_current_credential_and_invalidates_old_sessions(
        self,
    ) -> None:
        owner = self._bootstrap()
        self._create_worker(owner)
        first = self.identities.authenticate(
            display_name="Worker One", credential=self.WORKER_CREDENTIAL
        )
        with self.assertRaises(AuthorizationError):
            self.identities.rotate_credential(
                first,
                current_credential="incorrect-current-value",
                new_credential="replacement-credential-one",
            )
        self.identities.require_role(first, Role.WORKER)

        rotated = self.identities.rotate_credential(
            first,
            current_credential=self.WORKER_CREDENTIAL,
            new_credential="replacement-credential-one",
        )
        self.identities.require_role(rotated, Role.WORKER)
        with self.assertRaises(AuthorizationError):
            self.identities.require_role(first, Role.WORKER)
        with self.assertRaises(AuthorizationError):
            self.identities.authenticate(
                display_name="Worker One", credential=self.WORKER_CREDENTIAL
            )
        replacement = self.identities.authenticate(
            display_name="Worker One", credential="replacement-credential-one"
        )
        self.identities.require_role(replacement, Role.WORKER)

    def test_forged_verified_principal_objects_cannot_authorize(self) -> None:
        owner = self._bootstrap()
        with self.assertRaises(TypeError):
            VerifiedPrincipal(
                object(),
                principal_id=owner.principal_id,
                display_name=owner.display_name,
                session_id=owner.session_id,
                session_secret=b"not-the-real-session-secret",
                issued_at=owner.issued_at,
                expires_at=owner.expires_at,
            )

        forged = object.__new__(VerifiedPrincipal)
        object.__setattr__(forged, "_principal_id", owner.principal_id)
        object.__setattr__(forged, "_display_name", owner.display_name)
        object.__setattr__(forged, "_session_id", owner.session_id)
        object.__setattr__(forged, "_session_secret", b"not-the-real-session-secret")
        object.__setattr__(forged, "_issued_at", owner.issued_at)
        object.__setattr__(forged, "_expires_at", owner.expires_at)
        with self.assertRaises(AuthorizationError):
            self.identities.require_role(forged, Role.OWNER)

    def test_expired_and_revoked_sessions_are_denied(self) -> None:
        owner = self._bootstrap()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                UPDATE authenticated_sessions
                SET issued_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now', '-2 seconds'),
                    expires_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now', '-1 second')
                WHERE session_id = ?
                """,
                (owner.session_id,),
            )
        with self.assertRaises(AuthorizationError):
            self.identities.verify(owner)

        current = self.identities.authenticate(
            display_name="Owner One", credential=self.OWNER_CREDENTIAL
        )
        self.identities.revoke_session(current)
        with self.assertRaises(AuthorizationError):
            self.identities.verify(current)

    def test_owner_cannot_remove_or_disable_the_last_enabled_owner(self) -> None:
        owner = self._bootstrap()
        with self.assertRaisesRegex(AuthorizationError, "last enabled owner"):
            self.identities.set_roles(
                owner, display_name="Owner One", roles={Role.OBSERVER}
            )
        with self.assertRaisesRegex(AuthorizationError, "last enabled owner"):
            self.identities.disable_principal(owner, display_name="Owner One")
        self.identities.require_role(owner, Role.OWNER)

    def test_session_ttl_is_strictly_bounded(self) -> None:
        with self.assertRaises(ValueError):
            self.identities.bootstrap_owner(
                display_name="Owner One",
                credential=self.OWNER_CREDENTIAL,
                session_ttl_seconds=MAX_SESSION_TTL_SECONDS + 1,
            )
        self.assertEqual(self.store.query("SELECT * FROM principals"), [])

    def test_role_vocabulary_is_closed(self) -> None:
        self.assertEqual(
            {role.value for role in Role},
            {
                "owner",
                "worker",
                "evaluator",
                "release",
                "observer",
                "provider_attestor",
                "human_acceptor",
                "business_reviewer",
                "system",
            },
        )


if __name__ == "__main__":
    unittest.main()
