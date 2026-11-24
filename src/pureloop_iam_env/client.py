from typing import Any, Dict
from openenv.core.client_types import StepResult
from openenv.core.env_client import EnvClient

from .models import IAMObservation, IAMPolicyAction, IAMState


class IAMLeastPrivilegeClient(EnvClient[IAMPolicyAction, IAMObservation, IAMState]):
    def _step_payload(self, action: IAMPolicyAction) -> Dict[str, Any]:
        return {"statements": action.statements}

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[IAMObservation]:
        obs_data = payload.get("observation") if isinstance(payload.get("observation"), dict) else payload
        obs = IAMObservation(
            done=bool(payload.get("done", obs_data.get("done", False))),
            reward=float(payload.get("reward", obs_data.get("reward", 0.0))),
            role_name=obs_data.get("role_name", payload.get("role_name", "")),
            target_bucket=obs_data.get("target_bucket", payload.get("target_bucket", "")),
            required_actions=obs_data.get("required_actions", payload.get("required_actions", [])),
            current_statements=obs_data.get("current_statements", payload.get("current_statements", [])),
            last_check_summary=obs_data.get("last_check_summary", payload.get("last_check_summary", "")),
            violations=obs_data.get("violations", payload.get("violations", [])),
        )
        return StepResult(observation=obs, reward=obs.reward, done=obs.done)

    def _parse_state(self, payload: Dict[str, Any]) -> IAMState:
        return IAMState(
            episode_id=payload.get("episode_id"),
            step_count=int(payload.get("step_count", 0)),
            role_name=payload.get("role_name", "app-worker-role"),
            target_bucket=payload.get("target_bucket", "arn:aws:s3:::pureloop-prod-artifacts"),
            max_steps=int(payload.get("max_steps", 5)),
            current_statements=payload.get("current_statements", []),
        )
