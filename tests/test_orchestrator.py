"""
Tests for osint_core.orchestrator module
"""

import pytest

from osint_core.orchestrator import (
    OrchestratorAgent,
    ExecutionStatus,
    create_orchestrator,
    list_skills,
    get_skill,
    SKILLS_REGISTRY,
)
from osint_core.policy import PolicyDecision


def test_create_orchestrator():
    """Test orchestrator agent creation"""
    agent = create_orchestrator()
    assert isinstance(agent, OrchestratorAgent)
    assert agent.role == "orchestrator"
    assert len(agent.skills) > 0


def test_list_skills():
    """Test skills registry listing"""
    skills = list_skills()
    assert isinstance(skills, dict)
    assert "resource_links" in skills
    assert "dns_records" in skills
    assert "http_headers" in skills


def test_get_skill():
    """Test individual skill retrieval"""
    skill = get_skill("resource_links")
    assert skill is not None
    assert skill.name == "Resource Links"
    assert skill.canonical_name == "resource_links"
    assert skill.requires_authorization is False

    # Test conditional skill
    http_skill = get_skill("http_headers")
    assert http_skill is not None
    assert http_skill.requires_authorization is True


def test_get_nonexistent_skill():
    """Test retrieval of non-existent skill"""
    skill = get_skill("nonexistent_skill")
    assert skill is None


def test_create_context_valid_input():
    """Test execution context creation with valid input"""
    agent = create_orchestrator()
    context = agent.create_context(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links"],
        authorized_target=False,
        passive_only=True,
    )

    assert context.run_id.startswith("run_")
    assert context.indicator_type == "domain"
    assert context.normalized_indicator == "example.com"
    assert len(context.indicator_hash) == 64  # SHA256 hex
    assert context.requested_modules == ["resource_links"]
    assert context.authorized_target is False
    assert context.passive_only is True
    assert len(context.errors) == 0


def test_create_context_invalid_input():
    """Test execution context creation with invalid input"""
    agent = create_orchestrator()
    context = agent.create_context(
        raw_indicator="<script>alert('xss')</script>",
        indicator_type_hint="Auto",
        requested_modules=["resource_links"],
        authorized_target=False,
        passive_only=True,
    )

    assert context.indicator_type == "unknown"
    assert context.normalized_indicator == ""
    assert len(context.errors) > 0


def test_execute_workflow_with_valid_domain():
    """Test full workflow execution with valid domain"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links", "dns_records"],
        authorized_target=False,
        passive_only=True,
    )

    assert workflow.validation_result.ok is True
    assert workflow.context.indicator_type == "domain"
    assert workflow.policy_evaluation.decision == PolicyDecision.ALLOW
    assert len(workflow.policy_evaluation.allowed_modules) == 2
    assert "resource_links" in workflow.policy_evaluation.allowed_modules
    assert "dns_records" in workflow.policy_evaluation.allowed_modules
    assert len(workflow.skill_results) == 2
    assert workflow.duration_ms > 0


def test_execute_workflow_blocks_unauthorized_modules():
    """Test that unauthorized modules are blocked"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links", "http_headers"],
        authorized_target=False,  # Not authorized
        passive_only=True,
    )

    assert workflow.validation_result.ok is True
    assert workflow.policy_evaluation.decision == PolicyDecision.CONSTRAIN
    assert "resource_links" in workflow.policy_evaluation.allowed_modules
    assert "http_headers" in workflow.policy_evaluation.blocked_modules
    # Only resource_links should be executed
    assert len([r for r in workflow.skill_results if r.status == ExecutionStatus.COMPLETED]) == 1


def test_execute_workflow_allows_authorized_modules():
    """Test that authorized modules are allowed when authorized"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["http_headers"],
        authorized_target=True,  # Authorized
        passive_only=False,  # Not passive-only mode
    )

    assert workflow.validation_result.ok is True
    assert "http_headers" in workflow.policy_evaluation.allowed_modules
    assert len(workflow.policy_evaluation.blocked_modules) == 0


def test_execute_workflow_with_invalid_input():
    """Test workflow execution with invalid input"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="!!!invalid!!!",
        indicator_type_hint="Auto",
        requested_modules=["resource_links"],
        authorized_target=False,
        passive_only=True,
    )

    assert workflow.validation_result.ok is False
    assert len(workflow.skill_results) == 0
    assert workflow.correction_verb == "REVERT"


def test_execute_workflow_blocks_wrong_indicator_type():
    """Test that skills requiring specific indicator types are blocked"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="username123",
        indicator_type_hint="Username",
        requested_modules=["dns_records"],  # Requires domain
        authorized_target=False,
        passive_only=True,
    )

    assert workflow.validation_result.ok is True
    assert workflow.context.indicator_type == "username"
    assert "dns_records" in workflow.policy_evaluation.allowed_modules
    # DNS skill should be blocked because username is not compatible
    dns_result = next((r for r in workflow.skill_results if r.skill_name == "DNS Records"), None)
    assert dns_result is not None
    assert dns_result.status == ExecutionStatus.BLOCKED


def test_drift_detection_with_policy_violations():
    """Test drift detection when policy violations occur"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["http_headers"],  # Requires auth
        authorized_target=False,  # No auth
        passive_only=True,
    )

    # Should detect policy drift
    assert workflow.drift_vector["policy"] > 0
    assert workflow.correction_verb in ["CONSTRAIN", "REVERT"]


def test_correction_verb_choices():
    """Test that correction verbs follow the priority rules"""
    agent = create_orchestrator()

    # Low drift should result in OBSERVE
    workflow1 = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links"],
        authorized_target=False,
        passive_only=True,
    )
    assert workflow1.correction_verb == "OBSERVE"

    # Policy violation should result in CONSTRAIN or REVERT
    workflow2 = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["http_headers"],
        authorized_target=False,
        passive_only=True,
    )
    assert workflow2.correction_verb in ["CONSTRAIN", "REVERT"]


def test_skill_execution_timing():
    """Test that skill execution tracks duration"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links"],
        authorized_target=False,
        passive_only=True,
    )

    assert workflow.duration_ms > 0
    for result in workflow.skill_results:
        if result.status == ExecutionStatus.COMPLETED:
            assert result.duration_ms >= 0


def test_skills_registry_structure():
    """Test that skills registry has correct structure"""
    for skill_name, skill in SKILLS_REGISTRY.items():
        assert skill.canonical_name == skill_name
        assert isinstance(skill.name, str)
        assert isinstance(skill.description, str)
        assert isinstance(skill.required_indicator_types, list)
        assert isinstance(skill.tools, list)
        assert isinstance(skill.requires_authorization, bool)
        assert skill.category in ["validation", "passive_lookup", "conditional_fetch", "analysis"]


def test_url_parsing_skill():
    """Test URL parsing skill with URL indicator"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="https://example.com/path",
        indicator_type_hint="URL",
        requested_modules=["local_url_parse"],
        authorized_target=False,
        passive_only=True,
    )

    assert workflow.validation_result.ok is True
    assert workflow.context.indicator_type == "url"
    assert len(workflow.skill_results) == 1
    result = workflow.skill_results[0]
    assert result.status == ExecutionStatus.COMPLETED
    assert "scheme" in result.data


def test_multiple_modules_execution():
    """Test execution of multiple modules in parallel"""
    agent = create_orchestrator()
    workflow = agent.execute_workflow(
        raw_indicator="example.com",
        indicator_type_hint="Domain",
        requested_modules=["resource_links", "dns_records"],
        authorized_target=False,
        passive_only=True,
    )

    assert len(workflow.skill_results) == 2
    completed = [r for r in workflow.skill_results if r.status == ExecutionStatus.COMPLETED]
    assert len(completed) == 2
