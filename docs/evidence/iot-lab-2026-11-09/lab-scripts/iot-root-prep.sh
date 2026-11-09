#!/bin/bash
# WSL lab only: Mosquitto with password auth + per-user topic ACLs on loopback.
set -e
install -d -o sabih -g sabih -m 700 /home/sabih/.linxai-iot /home/sabih/.linxai-iot/state
for u in linxai lab-device; do
  f=/home/sabih/.linxai-iot/$([ $u = linxai ] && echo mqtt || echo device).pass
  [ -f $f ] || (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=' > $f)
  chown sabih:sabih $f; chmod 600 $f
done
rm -f /etc/mosquitto/linxai-lab.passwd
mosquitto_passwd -c -b /etc/mosquitto/linxai-lab.passwd linxai "$(cat /home/sabih/.linxai-iot/mqtt.pass)"
mosquitto_passwd -b /etc/mosquitto/linxai-lab.passwd lab-device "$(cat /home/sabih/.linxai-iot/device.pass)"
cat > /etc/mosquitto/linxai-lab.acl <<ACL
user linxai
topic read lab/+/state
topic read lab/humidity
topic write lab/+/set
user lab-device
topic readwrite lab/#
ACL
chown mosquitto:mosquitto /etc/mosquitto/linxai-lab.passwd /etc/mosquitto/linxai-lab.acl
chmod 600 /etc/mosquitto/linxai-lab.passwd /etc/mosquitto/linxai-lab.acl
cat > /etc/mosquitto/conf.d/linxai-lab.conf <<CONF
listener 1883 127.0.0.1
allow_anonymous false
password_file /etc/mosquitto/linxai-lab.passwd
acl_file /etc/mosquitto/linxai-lab.acl
CONF
systemctl restart mosquitto && systemctl is-active mosquitto
