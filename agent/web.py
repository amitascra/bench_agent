from __future__ import annotations

import json
import logging
import os
from base64 import b64decode
from functools import wraps

from flask import Flask, Response, jsonify, request
from passlib.hash import pbkdf2_sha256 as pbkdf2
from redis.exceptions import ConnectionError as RedisConnectionError
from rq.exceptions import NoSuchJobError
from rq.job import Job as RQJob

from agent.base import AgentException
from agent.exceptions import BenchNotExistsException, SiteNotExistsException
from agent.job import Job as AgentJob
from agent.job import JobModel, connection
from agent.server import Server
from agent.ssh import SSHProxy

log = logging.getLogger("werkzeug")
log.handlers = []

application = Flask(__name__)

SENSITIVE_CONFIG_KEYS = {
    "access_token",
    "redis_port",
    "redis_password",
    "db_password",
    "db_user",
    "db_host",
    "db_port",
}


def validate_bench(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        bench = kwargs.get("bench")
        if bench:
            Server().get_bench(bench)
        return fn(*args, **kwargs)
    return wrapper


def validate_bench_and_site(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        site = kwargs.get("site")
        bench = kwargs.get("bench")
        if bench:
            bench_obj = Server().get_bench(bench)
            bench_obj.get_site(site)
        return fn(*args, **kwargs)
    return wrapper


@application.before_request
def validate_access_token():
    exempt_endpoints = ["get_metrics"]
    if request.endpoint in exempt_endpoints:
        return None

    try:
        if application.debug:
            return None
        method, access_token = request.headers["Authorization"].split(" ")
        stored_hash = Server().config["access_token"]
        if method.lower() == "bearer" and pbkdf2.verify(access_token, stored_hash):
            return None
        access_token = b64decode(access_token).decode().split(":")[1]
        if method.lower() == "basic" and pbkdf2.verify(access_token, stored_hash):
            return None
    except Exception:
        pass

    response = jsonify({"message": "Unauthenticated"})
    response.headers.set("WWW-Authenticate", "Basic")
    return response, 401


@application.route("/authentication", methods=["POST"])
def reset_authentication_token():
    data = request.json
    Server().setup_authentication(data["token"])
    return jsonify({"message": "Success"})


@application.route("/ping")
def ping():
    return jsonify({"message": "pong"})


@application.route("/server")
def server():
    return jsonify(Server().config)


@application.route("/server/status", methods=["POST"])
def server_status():
    return jsonify({"status": "running"})


@application.route("/benches")
def benches():
    return jsonify(Server().benches)


@application.route("/benches/<string:bench>")
@validate_bench
def bench(bench):
    return jsonify(Server().get_bench(bench).dump())


@application.route("/benches/<string:bench>/status", methods=["GET"])
@validate_bench
def bench_status(bench):
    bench_obj = Server().get_bench(bench)
    return jsonify(bench_obj.status)


@application.route("/benches/<string:bench>/sites")
@validate_bench
def bench_sites(bench):
    bench_obj = Server().get_bench(bench)
    return jsonify([site.name for site in bench_obj.sites])


@application.route("/benches/<string:bench>/sites/<string:site>")
@validate_bench_and_site
def site(bench, site):
    bench_obj = Server().get_bench(bench)
    site_obj = bench_obj.get_site(site)
    return jsonify(site_obj.dump())


@application.route("/benches/<string:bench>/sites/<string:site>/status", methods=["GET"])
@validate_bench_and_site
def site_status(bench, site):
    bench_obj = Server().get_bench(bench)
    site_obj = bench_obj.get_site(site)
    return jsonify(site_obj.status)


@application.route("/jobs")
def jobs():
    return jsonify([job.to_dict() for job in AgentJob.get_all()])


@application.route("/jobs/<int:id>")
def job(id):
    job = AgentJob.get(id)
    if not job:
        return jsonify({"message": "Job not found"}), 404
    return jsonify(job.to_dict())


@application.route("/jobs/<string:ids>")
def jobs_by_ids(ids):
    job_ids = [int(id) for id in ids.split(",")]
    return jsonify([job.to_dict() for job in AgentJob.get_all(job_ids)])


@application.route("/ssh/users", methods=["POST"])
def ssh_users():
    return jsonify(SSHProxy().users())


if __name__ == "__main__":
    application.run(host="0.0.0.0", port=8000)
