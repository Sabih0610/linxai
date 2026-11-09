"""IoT acceptance (MQTT + Modbus/TCP) against lab devices or the local simulator.

Ordinary owner; `--assets` names a private JSON file with a `modbus` asset and an
`mqtt` asset (see docs/IOT.md). Uses the real OperationService, typed IoT actions
and the fixed worker; independent clients read the devices back after each change.
    LINXAI_TEST_IOT_LAB=1 python3 -B scripts/accept_iot.py --assets assets.json --modbus plc --mqtt home
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def modbus_read(asset, point):
    from pymodbus.client import ModbusTcpClient
    spec = asset["points"][point]
    client = ModbusTcpClient(asset["host"], port=asset["port"], timeout=5); client.connect()
    try:
        if spec["kind"] == "holding":
            return client.read_holding_registers(spec["address"], 1, slave=asset["unit"]).registers[0]
        return bool(client.read_coils(spec["address"], 1, slave=asset["unit"]).bits[0])
    finally:
        client.close()


def mqtt_retained(asset, topic, password=None, wait=3.0):
    import paho.mqtt.client as mqtt
    got = {}
    client = mqtt.Client(client_id="linxai-accept-" + uuid4().hex[:8], clean_session=True)
    client.username_pw_set(asset["username"], password or Path(asset["password_file"]).read_text().strip())
    client.on_message = lambda _c, _u, msg: got.setdefault("value", msg.payload.decode())
    client.connect(asset["host"], asset["port"], 30); client.loop_start(); client.subscribe(topic, 1)
    deadline = time.monotonic() + wait
    while "value" not in got and time.monotonic() < deadline:
        time.sleep(0.1)
    client.loop_stop(); client.disconnect()
    return got.get("value")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--modbus", required=True)
    parser.add_argument("--mqtt", required=True)
    parser.add_argument("--out", default="iot-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_IOT_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_IOT_LAB=1 against lab devices"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry, InvalidParameters
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid, assets, steps = os.getuid(), json.loads(Path(args.assets).read_text()), {}
    plc, home = assets[args.modbus], assets[args.mqtt]

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:220], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-iot-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        def service_for(values):
            registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(values))
            return registry, OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        registry, service = service_for(assets)

        def inspect(asset):
            r = service.run({"action": "iot.inspect", "parameters": {"asset": asset}})
            return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})

        def change_and_restore(asset, point, value, independent):
            _, before = inspect(asset)
            prior = before["points"][point]
            token = str(uuid4())
            changed = service.run({"action": "iot.point.set", "parameters": {"asset": asset, "point": point, "value": value,
                                   "expected_revision": before["revision"], "transaction_id": token}})
            out = json.loads(changed.stdout) if changed.stdout.strip().startswith("{") else {}
            after_change = independent()
            step(f"{asset}_{point}_set_verified", changed.status == "succeeded" and changed.verified
                 and changed.recovery == "available_for_review" and after_change == value,
                 prior=prior, device=after_change, reason=changed.reason)
            replay = service.run({"action": "iot.point.set", "parameters": {"asset": asset, "point": point, "value": prior,
                                  "expected_revision": out.get("revision", "0" * 64), "transaction_id": token}})
            step(f"{asset}_{point}_replay_refused", replay.status != "succeeded", status=replay.status)
            restored = service.run(out["restoration"]) if out.get("restoration") else None
            back = independent()
            step(f"{asset}_{point}_restore_verified", restored is not None and restored.status == "succeeded"
                 and restored.verified and back == prior, device=back)

        r, plc_view = inspect(args.modbus)
        step("modbus_inspect", r.status == "succeeded" and r.verified and set(plc_view.get("points", {})) == set(plc["points"]),
             points=plc_view.get("points"), reason=r.reason, err=r.stderr[-200:])
        r, home_view = inspect(args.mqtt)
        step("mqtt_inspect", r.status == "succeeded" and r.verified and None not in home_view.get("points", {None: None}).values(),
             points=home_view.get("points"))

        change_and_restore(args.modbus, "setpoint", 25, lambda: modbus_read(plc, "setpoint"))
        change_and_restore(args.modbus, "pump", True, lambda: modbus_read(plc, "pump"))
        change_and_restore(args.mqtt, "lamp", "ON", lambda: mqtt_retained(home, home["points"]["lamp"]["state_topic"]))
        change_and_restore(args.mqtt, "fan", 3, lambda: (lambda v: int(v) if v and v.isdigit() else v)(
            mqtt_retained(home, home["points"]["fan"]["state_topic"])))

        refused = {}
        for label, params in {"out_of_bounds": {"point": "setpoint", "value": 99}, "read_only": {"point": "temperature", "value": 1},
                              "wrong_type": {"point": "pump", "value": 1}}.items():
            try:
                registry.prepare("iot.point.set", {"asset": args.modbus, "expected_revision": "0" * 64, "transaction_id": str(uuid4()), **params})
                refused[label] = "NOT REFUSED"
            except InvalidParameters:
                refused[label] = "refused"
        step("bounds_and_read_only_refused_before_dispatch", all(v == "refused" for v in refused.values()), **refused)
        stale = service.run({"action": "iot.point.set", "parameters": {"asset": args.modbus, "point": "setpoint", "value": 20,
                             "expected_revision": "0" * 64, "transaction_id": str(uuid4())}})
        step("stale_revision_refused", stale.status != "succeeded" and not stale.executed and modbus_read(plc, "setpoint") != 20,
             status=stale.status)

        # A device that never answers: the broker accepts the publish, but LINxAI must not report success.
        ghost = dict(home, points={**home["points"], "ghost": {"state_topic": "lab/ghost/state", "command_topic": "lab/ghost/set", "values": ["ON", "OFF"]}})
        _, ghost_service = service_for({args.mqtt: ghost})
        ghost_view = ghost_service.run({"action": "iot.inspect", "parameters": {"asset": args.mqtt}})
        dead = ghost_service.run({"action": "iot.point.set", "parameters": {"asset": args.mqtt, "point": "ghost", "value": "ON",
                                  "expected_revision": json.loads(ghost_view.stdout)["revision"], "transaction_id": str(uuid4())}})
        step("silent_device_not_reported_as_success", ghost_view.status == "succeeded" and dead.status != "succeeded"
             and not dead.verified, status=dead.status, reason=dead.reason)

        # Broker ACL: the controller account cannot forge a device's state topic.
        import paho.mqtt.client as mqtt
        before = mqtt_retained(home, home["points"]["lamp"]["state_topic"])
        forger = mqtt.Client(client_id="linxai-forge-" + uuid4().hex[:6]); forger.username_pw_set(home["username"], Path(home["password_file"]).read_text().strip())
        forger.connect(home["host"], home["port"], 30); forger.loop_start()
        forger.publish(home["points"]["lamp"]["state_topic"], "FORGED", qos=1, retain=True).wait_for_publish(5)
        time.sleep(1); forger.loop_stop(); forger.disconnect()
        step("broker_acl_blocks_forged_state", mqtt_retained(home, home["points"]["lamp"]["state_topic"]) == before, state=before)

        wrong = dict(home, password_file=str(Path(temp) / "wrong.pass")); Path(wrong["password_file"]).write_text("not-the-password\n")
        os.chmod(wrong["password_file"], 0o600)
        _, wrong_service = service_for({args.mqtt: wrong})
        denied = wrong_service.run({"action": "iot.inspect", "parameters": {"asset": args.mqtt}})
        step("wrong_broker_credentials_refused", denied.status != "succeeded", status=denied.status)

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
