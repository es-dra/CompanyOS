"""Public API for the CompanyOS durable runtime kernel."""

from .adapters import (
    AdapterConformanceReport,
    AdapterReceipt,
    WorkflowAdapter,
    run_adapter_conformance,
)
from .backup import create_online_backup, restore_backup
from .authority import (
    AuthorityBounds,
    AuthorityRef,
    CompiledGoalAuthority,
    CompiledTaskAuthority,
    ProgramSpec,
    ProgramState,
    ProjectSpec,
)
from .authority_compiler import (
    compile_goal_authority,
    compile_program,
    compile_project,
    compile_task_authority,
    validate_goal_authority,
    validate_program_graph,
    validate_task_authority,
)
from .context import ContextRegistry
from .compiler import compile_goal, compile_task
from .domain_packs import (
    AOSCoreBundle,
    CORE_CONTRACT_VERSION,
    DomainPack,
    DomainPackConformanceReport,
    FixtureDomainPack,
    compile_domain_pack,
    run_cross_domain_conformance,
    run_domain_pack_conformance,
)
from .evaluation import (
    ActiveRulePromotionRecord,
    EvaluationRegistry,
    LimitedRulePromotionRecord,
    LimitedRulePromotionRequest,
    SealedCustodyAttestation,
    SealedCustodyVerifier,
)
from .evidence import EvidenceRegistry
from .integration import IntegrationQueue
from .identity import IdentityManager, Role, VerifiedPrincipal
from .kernel import RuntimeKernel
from .leases import LeaseManager, LeaseRecord
from .memory import MemoryRegistry
from .observations import ObservationRegistry
from .operator import operator_snapshot
from .policy import PolicyEngine
from .scheduler import TaskScheduler
from .types import (
    Capability,
    EvidenceState,
    GoalSpec,
    GoalState,
    IntegrationState,
    RuntimeSurfaceSpec,
    TaskSpec,
    TaskState,
)
from .workflow import EffectReceipt, OutboxEffect

__all__ = [
    "ActiveRulePromotionRecord",
    "AOSCoreBundle",
    "AdapterConformanceReport",
    "AdapterReceipt",
    "AuthorityBounds",
    "AuthorityRef",
    "Capability",
    "CORE_CONTRACT_VERSION",
    "ContextRegistry",
    "create_online_backup",
    "compile_goal",
    "compile_domain_pack",
    "compile_goal_authority",
    "compile_program",
    "compile_project",
    "compile_task",
    "compile_task_authority",
    "CompiledGoalAuthority",
    "CompiledTaskAuthority",
    "DomainPack",
    "DomainPackConformanceReport",
    "EvidenceState",
    "EffectReceipt",
    "EvidenceRegistry",
    "EvaluationRegistry",
    "FixtureDomainPack",
    "GoalSpec",
    "GoalState",
    "IntegrationState",
    "IntegrationQueue",
    "IdentityManager",
    "LeaseManager",
    "LeaseRecord",
    "LimitedRulePromotionRecord",
    "LimitedRulePromotionRequest",
    "MemoryRegistry",
    "ObservationRegistry",
    "operator_snapshot",
    "OutboxEffect",
    "PolicyEngine",
    "ProgramSpec",
    "ProgramState",
    "ProjectSpec",
    "RuntimeKernel",
    "Role",
    "restore_backup",
    "run_adapter_conformance",
    "run_cross_domain_conformance",
    "run_domain_pack_conformance",
    "RuntimeSurfaceSpec",
    "SealedCustodyAttestation",
    "SealedCustodyVerifier",
    "TaskSpec",
    "TaskScheduler",
    "TaskState",
    "validate_goal_authority",
    "validate_program_graph",
    "validate_task_authority",
    "VerifiedPrincipal",
    "WorkflowAdapter",
]

__version__ = "0.2.0.dev2"
