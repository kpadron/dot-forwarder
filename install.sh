#/usr/bin/env bash

systemctl stop dot-forwarder > /dev/null 2>&1
systemctl disable dot-forwarder > /dev/null 2>&1
cp "$1" /usr/local/bin/dot-forwarder &&
chmod 755 /usr/local/bin/dot-forwarder &&
cp dot-forwarder.service /etc/systemd/system/dot-forwarder.service &&
chmod 644 /etc/systemd/system/dot-forwarder.service &&
echo "dot-forwarder installed" ||
(echo "dot-forwarder not installed, undoing changes" &&
./uninstall.sh)

systemctl daemon-reload &&
systemctl start dot-forwarder &&
systemctl enable dot-forwarder &&
echo "dot-forwarder enabled as a service" ||
echo "dot-forwarder not enabled as a service"
