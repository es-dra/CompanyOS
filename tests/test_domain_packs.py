from __future__ import annotations

import json
import unittest
from pathlib import Path

from companyos_runtime.domain_packs import (
    AOSCoreBundle,
    FixtureDomainPack,
    compile_domain_pack,
    run_cross_domain_conformance,
    run_domain_pack_conformance,
)
from companyos_runtime.errors import ContractError


FIXTURES = Path(__file__).parent / "fixtures" / "domain_packs"


def load_pack(name: str) -> FixtureDomainPack:
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return FixtureDomainPack.from_dict(data)


class DomainPackConformanceTests(unittest.TestCase):
    def test_companyos_and_afs_share_the_same_strict_core(self) -> None:
        report = run_cross_domain_conformance(
            [load_pack("companyos.json"), load_pack("agentflow-studio.json")]
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["contract_version"], "aos.core.v0.1")
        self.assertEqual(
            {item["pack_id"] for item in report["packs"]},
            {"companyos", "agentflow-studio"},
        )
        self.assertTrue(all(item["status"] == "passed" for item in report["packs"]))
        self.assertEqual(report["checks"]["unique_core_ids"], "passed")
        self.assertIn("human_acceptance", report["non_claims"])

    def test_each_domain_pack_is_deterministic_and_roundtrippable(self) -> None:
        for fixture in ("companyos.json", "agentflow-studio.json"):
            pack = load_pack(fixture)
            report = run_domain_pack_conformance(pack)
            bundle = compile_domain_pack(pack)
            self.assertEqual(report.status, "passed")
            self.assertEqual(AOSCoreBundle.from_wire(bundle.to_wire()), bundle)
            self.assertEqual(report.checks["authority_subset"], "passed")

    def test_domain_payload_cannot_leak_into_core_bundle(self) -> None:
        wire = compile_domain_pack(load_pack("agentflow-studio.json")).to_wire()
        wire["storyboard"] = {"shots": []}
        with self.assertRaisesRegex(ContractError, "unknown fields"):
            AOSCoreBundle.from_wire(wire)

    def test_core_bundle_rejects_non_digest_provenance(self) -> None:
        wire = compile_domain_pack(load_pack("companyos.json")).to_wire()
        wire["source_digests"]["goal_authoring"] = "not-a-digest"
        with self.assertRaisesRegex(ContractError, "SHA-256"):
            AOSCoreBundle.from_wire(wire)

    def test_pack_adapter_namespace_is_fail_closed(self) -> None:
        data = json.loads(
            (FIXTURES / "agentflow-studio.json").read_text(encoding="utf-8")
        )
        data["task_authoring"]["task_packet"]["workflow_steps"][0]["adapter"] = (
            "companyos.local"
        )
        with self.assertRaisesRegex(ContractError, "namespaced by pack_id"):
            compile_domain_pack(FixtureDomainPack.from_dict(data))

    def test_core_bundle_wire_rejects_foreign_pack_adapter(self) -> None:
        wire = compile_domain_pack(load_pack("agentflow-studio.json")).to_wire()
        wire["task_spec"]["workflow_steps"][0]["adapter"] = "companyos.local-projection"
        with self.assertRaisesRegex(ContractError, "namespaced by pack_id"):
            AOSCoreBundle.from_wire(wire)

    def test_core_bundle_wire_rejects_empty_adapter_suffix(self) -> None:
        wire = compile_domain_pack(load_pack("agentflow-studio.json")).to_wire()
        wire["task_spec"]["workflow_steps"][0]["adapter"] = "agentflow-studio."
        with self.assertRaisesRegex(ContractError, "namespaced by pack_id"):
            AOSCoreBundle.from_wire(wire)

    def test_domain_extensions_cannot_expand_compiled_goal(self) -> None:
        data = json.loads((FIXTURES / "companyos.json").read_text(encoding="utf-8"))
        data["goal_authoring"]["goal_contract"]["customer_contract"] = "not-core"
        with self.assertRaisesRegex(ContractError, "unsupported fields"):
            compile_domain_pack(FixtureDomainPack.from_dict(data))


if __name__ == "__main__":
    unittest.main()
