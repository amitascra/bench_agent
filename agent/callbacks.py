import requests


def callback(job, connection, result, *args, **kwargs):
    from agent.server import Server

    bench_manager_url = Server().press_url
    requests.post(url=f"{bench_manager_url}/api/method/bench_manager.api.callbacks.callback", data={"job_id": job.id})
