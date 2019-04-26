#/usr/bin/env bash

systemctl stop dot-forwarder > /dev/null 2>&1 &&
systemctl disable dot-forwarder > /dev/null 2>&1 &&
systemctl daemon-reload &&
echo "dot-forwarder disabled as a service" ||
echo "dot-forwarder not disabled as a service, are you running with super user permissions, is it installed as a service?"

rm -f /usr/local/bin/dot-forwarder
rm -f /etc/systemd/system/dot-forwarder.service

[ ! -f /usr/local/bin/dot-forwarder ] &&
[ ! -f /etc/systemd/system/dot-forwarder.service ] &&
echo "dot-forwarder uninstalled" ||
echo "dot-forwarder not uninstalled, are you running with super user permissions?"
