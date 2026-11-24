import copy
from typing import Any, Optional
from openenv.core.env_server import Environment

from ..models import IAMObservation, IAMPolicyAction, IAMState
from .verifier import REQUIRED_S3_ACTIONS, verify_policy


INITIAL_BROKEN_POLICY = [
    {
        "Sid": "OverPermissiveStarter",
        "Effect": "Allow",
        "Action": ["*"],
        "Resource": ["*"],
    }
]


class IAMLeastPrivilegeEnv(Environment[IAMPolicyAction, IAMObservation, IAMState]):
    def __init__(self) -> None:
        super().__init__()
        self._state = IAMState()

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> IAMObservation:
        self._state = IAMState(
            episode_id=episode_id or "ep-0",
            step_count=0,
            role_name="app-worker-role",
            target_bucket="arn:aws:s3:::pureloop-prod-artifacts",
            max_steps=5,
            current_statements=copy.deepcopy(INITIAL_BROKEN_POLICY),
        )
        return IAMObservation(
            done=False,
            reward=0.0,
            role_name=self._state.role_name,
            target_bucket=self._state.target_bucket,
            required_actions=sorted(REQUIRED_S3_ACTIONS),
            current_statements=copy.deepcopy(self._state.current_statements),
            last_check_summary="Episode initialized with over-permissive policy.",
            violations=["Initial policy uses wildcard Action * and Resource *."],
        )

    def step(
        self,
        action: IAMPolicyAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IAMObservation:
        self._state.step_count += 1
        self._state.current_statements = copy.deepcopy(action.statements)

        passed, reward, violations, summary = verify_policy(
            statements=self._state.current_statements,
            target_bucket=self._state.target_bucket,
        )

        out_of_steps = self._state.step_count >= self._state.max_steps
        done = passed or out_of_steps
        if out_of_steps and not passed:
            summary = f"FAILED: max steps ({self._state.max_steps}) reached without passing."

        return IAMObservation(
            done=done,
            reward=reward,
            role_name=self._state.role_name,
            target_bucket=self._state.target_bucket,
            required_actions=sorted(REQUIRED_S3_ACTIONS),
            current_statements=copy.deepcopy(self._state.current_statements),
            last_check_summary=summary,
            violations=violations,
        )

    @property
    def state(self) -> IAMState:
        return self._state
