"""Simple CLI.

  cwe run  --profile examples/profiles/python-service.yaml --cmd "pytest -q" [--eval criteria.json]
  cwe replay .cwe_data/<session>/events.jsonl --cmd "..."   # replay a recording without AWS
  cwe serve                                                  # REST API
"""

from __future__ import annotations

import argparse
import json
import sys

from cwe.emulator import load_profile
from cwe.models import EmulatorProfile, EvalCriteria
from cwe.session import SessionManager


def cmd_run(a):
    profile = load_profile(a.profile) if a.profile else EmulatorProfile()
    mgr = SessionManager()
    sess = mgr.create(profile=profile)
    print(f"session {sess.info.session_id} sandbox {sess.info.sandbox_session_id} ws {sess.info.workspace_path}")
    try:
        sess.begin_run(a.title or "cli")
        for path in a.file or []:
            with open(path, encoding="utf-8") as f:
                sess.write_files({path.split("/")[-1]: f.read()})
        for c in a.cmd or []:
            r = sess.run_command(c)
            print(f"$ {c}\n{r.output}(exit={r.exit_code}, {r.execution_time:.2f}s)")
        if a.pytest:
            r = sess.run_pytest(a.pytest)
            print(r.output)
        sess.end_run()
        if a.eval:
            with open(a.eval, encoding="utf-8") as f:
                rep = sess.evaluate(EvalCriteria.model_validate(json.load(f)), task=a.task or "")
            print(json.dumps(rep.model_dump(mode="json"), indent=2, ensure_ascii=False))
        if a.snapshot:
            print(sess.snapshot("cli").model_dump_json())
        print("events:", mgr.events_path(sess.info.session_id))
    finally:
        mgr.close(sess.info.session_id)


def cmd_replay(a):
    from cwe.sandbox import ReplaySandbox

    mgr = SessionManager(sandbox_factory=lambda p: ReplaySandbox.from_jsonl(a.events, strict=not a.lenient))
    sess = mgr.create()
    sess.begin_run("replay")
    for c in a.cmd or []:
        r = sess.run_command(c)
        print(f"$ {c}\n{r.output}(exit={r.exit_code})")
    sess.end_run()
    if a.eval:
        with open(a.eval, encoding="utf-8") as f:
            rep = sess.evaluate(EvalCriteria.model_validate(json.load(f)), use_llm=False)
        print(json.dumps(rep.model_dump(mode="json"), indent=2, ensure_ascii=False))
    mgr.close(sess.info.session_id)


def cmd_reap(a):
    """Reclaims expired workload and Android Jobs (EKS) or Android hosts tagged with project whose cwe:expires-at has passed.
    Run periodically via cron / EventBridge: cwe reap --apply"""
    from datetime import datetime, timezone

    import boto3

    from cwe.config import get_settings

    st = get_settings()
    now = datetime.now(timezone.utc)
    if st.android_backend == "eks":
        from cwe.eks import EKSEmulatorHost
        from cwe.workload import EKSWorkloadHost

        jobs = EKSWorkloadHost.from_env(st).reap(apply=a.apply)
        print("deleted workload jobs:" if a.apply else "expired workload jobs (use --apply):", jobs)
        try:
            android_host = EKSEmulatorHost.from_env(st)
        except ValueError as e:   # workload-only environment without device images: nothing Android to reap
            print(f"android jobs skipped: {e}")
        else:
            jobs = android_host.reap(apply=a.apply)
            print("deleted android jobs:" if a.apply else "expired android jobs (use --apply):", jobs)
    elif st.android_backend == "ec2":
        ec2 = boto3.client("ec2", region_name=st.region)
        victims = []
        for r in ec2.describe_instances(Filters=[{"Name": "tag:project", "Values": [a.project]}, {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}])["Reservations"]:
            for i in r["Instances"]:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                exp = tags.get("cwe:expires-at")
                launched = i["LaunchTime"]
                expired = (exp and datetime.fromisoformat(exp) < now) or (not exp and (now - launched).total_seconds() > a.max_age_hours * 3600)
                print(f"{i['InstanceId']}  launched={launched:%Y-%m-%dT%H:%M}Z  expires={exp or '-'}  {'EXPIRED' if expired else 'ok'}")
                if expired:
                    victims.append(i["InstanceId"])
        if victims and a.apply:
            ec2.terminate_instances(InstanceIds=victims); print("terminated:", victims)
        elif victims:
            print("would terminate:", victims, "(use --apply)")
    else:
        raise ValueError("CWE_ANDROID_BACKEND must be eks | ec2")
    dp = boto3.client("bedrock-agentcore", region_name=st.region)
    for sess in dp.list_code_interpreter_sessions(codeInterpreterIdentifier=st.code_interpreter_id, status="READY").get("items", []):
        age = (now - sess["createdAt"]).total_seconds() / 3600
        print(f"sandbox {sess['sessionId']} age={age:.1f}h")
        if age > a.max_age_hours and a.apply:
            dp.stop_code_interpreter_session(codeInterpreterIdentifier=st.code_interpreter_id, sessionId=sess["sessionId"]); print("  stopped")


def cmd_skill(a):
    from cwe.skills import SkillStore

    mgr = SessionManager(); store = SkillStore(mgr.store, mgr.settings.skills_prefix)
    if a.action == "list":
        for sk in store.list():
            print(f"{sk['status']:9} {sk['name']:30} {sk['description']}")
    elif a.action == "show":
        sk = store.load(a.name); print(sk["body"] if sk else "not found")
    elif a.action == "approve":
        print("approved" if store.approve(a.name) else "not found")
    elif a.action == "distill":
        sess = mgr.open_recorded(a.session); d = sess.distill_skill(a.run)
        print("draft saved:", d["name"], "-", d["description"])


def cmd_android_setup(a):
    """Propose an emulator profile by reading the repository's Gradle configuration."""
    from cwe.android_setup import propose_profile

    profile, why = propose_profile(a.path, a.templates)
    print(json.dumps({"profile": profile.model_dump(), "evidence": why}, indent=2, ensure_ascii=False))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(profile.model_dump(), f, indent=2, ensure_ascii=False)
        print("wrote", a.out)


def cmd_android_pool(a):
    """Warm pool: pre-booted emulator hosts so a session starts in seconds instead of minutes."""
    from cwe.config import get_settings

    if get_settings().android_backend == "eks":
        raise SystemExit("EKS capacity is managed by Terraform android_desired_size; android-pool is only for the legacy EC2 backend")
    import secrets

    import boto3

    from cwe.android import AndroidEmulatorProfile, EC2EmulatorHost, _expires_at

    host = EC2EmulatorHost.from_env(use_pool=False)
    ssm = boto3.client("ssm", region_name=host.region)
    running = host.ec2.describe_instances(Filters=[{"Name": "tag:cwe:pool", "Values": ["ready"]}, {"Name": "instance-state-name", "Values": ["pending", "running"]}])["Reservations"]
    have = sum(len(r["Instances"]) for r in running)
    print(f"pool ready: {have}, target: {a.size}")
    for _ in range(max(0, a.size - have)):
        profile = AndroidEmulatorProfile()
        ami = host.ami_id or ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id")["Parameter"]["Value"]
        host.publish_token()                             # the token is delivered only via SSM SecureString
        user_data = host.render_user_data(profile, "", ttl_seconds=int(a.max_hours * 3600))   # pool hosts are bound to a session via /bind when claimed
        r = host.ec2.run_instances(ImageId=ami, InstanceType=host.instance_type, MinCount=1, MaxCount=1, CpuOptions={"NestedVirtualization": "enabled"},
                                   NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": host.subnet_id, "Groups": [host.security_group], "AssociatePublicIpAddress": host.associate_public_ip}],
                                   IamInstanceProfile={"Name": host.instance_profile}, UserData=user_data, MetadataOptions={"HttpTokens": "required"},
                                   BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3", "DeleteOnTermination": True}}],
                                   TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "cwe-emu-pool"}, {"Key": "project", "Value": host.project},
                                                                                           {"Key": "cwe:pool", "Value": "ready"}, {"Key": "cwe:expires-at", "Value": _expires_at(a.max_hours * 3600)}]}])
        iid = r["Instances"][0]["InstanceId"]
        ssm.put_parameter(Name=f"/{host.project}/pool/{iid}/token", Value=host.token, Type="SecureString", Overwrite=True)
        print("launched pool host", iid)
        host.token = secrets.token_urlsafe(24)   # the next host gets a different token


def cmd_eks_token(a):
    from cwe.config import get_settings
    from cwe.kube import exec_credential

    json.dump(exec_credential(a.cluster, a.region or get_settings().region), sys.stdout)


def cmd_eks_kubeconfig(a):
    from cwe.config import get_settings
    from cwe.kube import ensure_kubeconfig

    path, context = ensure_kubeconfig(a.cluster, a.region or get_settings().region, a.path)
    print(f"{path}\t{context}")


def cmd_serve(a):
    import ipaddress
    import os

    import uvicorn

    try:
        loopback = a.host == "localhost" or ipaddress.ip_address(a.host).is_loopback
    except ValueError:   # a hostname may resolve anywhere; treat it as non-loopback
        loopback = False
    if not loopback and not os.environ.get("CWE_API_KEY") and os.environ.get("CWE_ALLOW_UNAUTHENTICATED") != "1":
        raise SystemExit("refusing to listen on a non-loopback address without CWE_API_KEY (set CWE_ALLOW_UNAUTHENTICATED=1 to override)")
    uvicorn.run("cwe.api:app", host=a.host, port=a.port, reload=False)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cwe")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--profile"); r.add_argument("--title"); r.add_argument("--task")
    r.add_argument("--file", action="append"); r.add_argument("--cmd", action="append"); r.add_argument("--pytest")
    r.add_argument("--eval"); r.add_argument("--snapshot", action="store_true"); r.set_defaults(fn=cmd_run)
    rp = sub.add_parser("replay"); rp.add_argument("events"); rp.add_argument("--cmd", action="append")
    rp.add_argument("--eval"); rp.add_argument("--lenient", action="store_true"); rp.set_defaults(fn=cmd_replay)
    rr = sub.add_parser("reap", help="reclaim expired Android devices and stale sandbox sessions"); rr.add_argument("--apply", action="store_true")
    rr.add_argument("--project", default="cwe"); rr.add_argument("--max-age-hours", type=float, default=4.0); rr.set_defaults(fn=cmd_reap)
    sk = sub.add_parser("skill", help="list, show, approve or distil skills"); sk.add_argument("action", choices=["list", "show", "approve", "distill"])
    sk.add_argument("--name"); sk.add_argument("--session"); sk.add_argument("--run"); sk.set_defaults(fn=cmd_skill)
    ase = sub.add_parser("android-setup", help="propose an emulator profile from a Gradle project"); ase.add_argument("path")
    ase.add_argument("--templates", default="examples/profiles/android"); ase.add_argument("--out"); ase.set_defaults(fn=cmd_android_setup)
    ap = sub.add_parser("android-pool", help="maintain a warm pool of emulator hosts (legacy EC2 backend only)"); ap.add_argument("--size", type=int, default=1)
    ap.add_argument("--max-hours", type=float, default=4.0); ap.set_defaults(fn=cmd_android_pool)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000); s.set_defaults(fn=cmd_serve)
    kt = sub.add_parser("eks-token", help="kubectl exec credential plugin: print an EKS token from the caller's IAM credentials")
    kt.add_argument("--cluster", required=True); kt.add_argument("--region"); kt.set_defaults(fn=cmd_eks_token)
    kc = sub.add_parser("eks-kubeconfig", help="write a kubeconfig for the cluster using cwe eks-token, print its path and context")
    kc.add_argument("--cluster", required=True); kc.add_argument("--region"); kc.add_argument("--path"); kc.set_defaults(fn=cmd_eks_kubeconfig)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
