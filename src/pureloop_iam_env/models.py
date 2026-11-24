from typing import Any, Dict, List
from openenv.core.env_server import Action, Observation, State
from pydantic import Field


class IAMPolicyAction(Action):
    statements: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of IAM policy statements with Effect, Action, and Resource.",
    )


class IAMObservation(Observation):
    role_name: str = ""
    target_bucket: str = ""
    required_actions: List[str] = Field(default_factory=list)
    current_statements: List[Dict[str, Any]] = Field(default_factory=list)
    last_check_summary: str = ""
    violations: List[str] = Field(default_factory=list)


class IAMState(State):
    role_name: str = "app-worker-role"
    target_bucket: str = "arn:aws:s3:::pureloop-prod-artifacts"
    max_steps: int = 5
    current_statements: List[Dict[str, Any]] = Field(default_factory=list)
