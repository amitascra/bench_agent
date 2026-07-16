import requests


def callback(job, connection, result, *args, **kwargs):
    """RQ on_success/on_failure hook. job is the RQ Job; its id was set to our
    own JobModel row's id at enqueue time, so job.id doubles as the agent_job_id
    a caller can poll via GET /jobs/<id>. We also forward it as X-Agent-Job-Id's
    echoed value isn't available here, so job_id is simply this agent's own job id -
    the caller (bench_manager) is expected to have recorded which of its own
    Agent Job docs this corresponds to when it made the original request."""
    from agent.server import Server

    bench_manager_url = Server().press_url
    try:
        requests.post(
            url=f"{bench_manager_url}/api/method/bench_manager.bench_manager.api.callbacks.callback",
            data={"job_id": job.id},
            timeout=(5, 15),
        )
    except requests.exceptions.RequestException:
        # Best-effort - the caller can still poll GET /jobs/<id> if this fails.
        pass
