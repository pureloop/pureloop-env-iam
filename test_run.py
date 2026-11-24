from pureloop_iam_env import IAMLeastPrivilegeClient, IAMPolicyAction

with IAMLeastPrivilegeClient(base_url="http://127.0.0.1:8000").sync() as client:
    start = client.reset()
    print("Initial violations:", start.observation.violations)

    cheat = client.step(
        IAMPolicyAction(
            statements=[
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": ["*"],
                }
            ]
        )
    )
    print("Cheat reward:", cheat.reward, "Violations:", cheat.observation.violations)

with IAMLeastPrivilegeClient(base_url="http://127.0.0.1:8000").sync() as client:
    client.reset()
    good = client.step(
        IAMPolicyAction(
            statements=[
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::pureloop-prod-artifacts"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": ["arn:aws:s3:::pureloop-prod-artifacts/*"],
                },
            ]
        )
    )
    print("Good reward:", good.reward, "Done:", good.done, "Summary:", good.observation.last_check_summary)
