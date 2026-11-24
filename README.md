# pureloop-env-iam

AWS IAM least-privilege evaluation environment built with `openenv-core`, FastAPI, and Uvicorn.

## Run Server

```bash
uvicorn pureloop_iam_env.server.app:app --host 127.0.0.1 --port 8000
```

## Run Client Test

```bash
python test_run.py
```
