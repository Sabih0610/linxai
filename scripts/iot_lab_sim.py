"""Local IoT lab simulator (development only; never part of the installed product).

Modbus/TCP PLC on 127.0.0.1:5020 (unit 1): holding register 10 = setpoint (21),
coil 0 = pump (off), input register 0 = temperature in tenths of a degree (drifts).
MQTT devices (user `lab-device`): a lamp (ON/OFF) and a fan (0..3) that obey
`lab/<name>/set` and report retained state on `lab/<name>/state`, plus a read-only
humidity sensor on `lab/humidity`. Invalid commands are ignored, like real firmware.
    python3 -B scripts/iot_lab_sim.py --mqtt-password-file ~/.linxai-iot/device.pass
"""
import argparse
import asyncio
import random
import threading
import time


def mqtt_devices(host, port, password):
    import paho.mqtt.client as mqtt
    state = {"lamp": "OFF", "fan": "0"}
    valid = {"lamp": {"ON", "OFF"}, "fan": {"0", "1", "2", "3"}}
    client = mqtt.Client(client_id="lab-device-sim", clean_session=True)
    client.username_pw_set("lab-device", password)

    def publish_state(name):
        client.publish(f"lab/{name}/state", state[name], qos=1, retain=True)

    def on_connect(c, _u, _f, rc):
        c.subscribe([("lab/lamp/set", 1), ("lab/fan/set", 1)])
        for name in state:
            publish_state(name)

    def on_message(_c, _u, msg):
        name = msg.topic.split("/")[1]
        value = msg.payload.decode(errors="replace")
        if value in valid.get(name, ()):
            time.sleep(0.3)                       # device actuation delay
            state[name] = value
            publish_state(name)

    client.on_connect, client.on_message = on_connect, on_message
    client.connect(host, port, keepalive=30)
    client.loop_start()
    while True:
        client.publish("lab/humidity", str(random.randint(40, 60)), qos=1, retain=True)
        time.sleep(5)


async def modbus_plc(port):
    from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
    from pymodbus.server import StartAsyncTcpServer
    store = ModbusSlaveContext(di=ModbusSequentialDataBlock(0, [0] * 100), co=ModbusSequentialDataBlock(0, [0] * 100),
                               hr=ModbusSequentialDataBlock(0, [0] * 100), ir=ModbusSequentialDataBlock(0, [0] * 100), zero_mode=True)
    store.setValues(3, 10, [21])
    context = ModbusServerContext(slaves={1: store}, single=False)

    async def drift():
        while True:
            store.setValues(4, 0, [random.randint(200, 260)])
            await asyncio.sleep(2)
    asyncio.create_task(drift())
    await StartAsyncTcpServer(context=context, address=("127.0.0.1", port))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modbus-port", type=int, default=5020)
    parser.add_argument("--mqtt-host", default="127.0.0.1")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-password-file", required=True)
    args = parser.parse_args()
    password = open(args.mqtt_password_file).read().strip()
    threading.Thread(target=mqtt_devices, args=(args.mqtt_host, args.mqtt_port, password), daemon=True).start()
    asyncio.run(modbus_plc(args.modbus_port))


if __name__ == "__main__":
    main()
