#!/bin/bash

codename=$(lsb_release -cs)
logfile=/var/tmp/userdata_ubuntu_${codename}.log

# --------------------------------

date > $logfile
echo "Install packages" >> $logfile 2>&1
apt update --yes >> $logfile 2>&1
apt install --yes curl file jq netcat parted python3 python3-apt python3-pip python3-virtualenv vim wget >> $logfile 2>&1
apt install --yes locales net-tools nmap >> $logfile 2>&1

# --------------------------------

date >> $logfile
echo "Add boostrap user" >> $logfile 2>&1
useradd --comment "Bootstrap user" --create-home --shell /bin/bash --user-group --groups "sudo,users" bootstrap >> $logfile 2>&1
mkdir -p /home/bootstrap/.ssh >> $logfile 2>&1
chmod 700 /home/bootstrap/.ssh >> $logfile 2>&1

if [[ -d /opt/vultr ]]; then
	cp /root/.ssh/authorized_keys /home/bootstrap/.ssh >> $logfile 2>&1
else
	cp /home/ubuntu/.ssh/authorized_keys /home/bootstrap/.ssh >> $logfile 2>&1
fi
chown -R bootstrap:bootstrap /home/bootstrap >> $logfile 2>&1
/bin/ls -Rals /home/bootstrap >> $logfile 2>&1

# --------------------------------

date >> $logfile
echo "Done" >> $logfile 2>&1

# --------------------------------

exit 0
