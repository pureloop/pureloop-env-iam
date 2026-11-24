from openenv.core.env_server.http_server import create_app

from ..models import IAMObservation, IAMPolicyAction
from .environment import IAMLeastPrivilegeEnv


app = create_app(
    IAMLeastPrivilegeEnv,
    IAMPolicyAction,
    IAMObservation,
    env_name="pureloop_iam_env",
)