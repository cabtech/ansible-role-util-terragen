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
# add disk

mountpoint=/data
fstype=ext4

lsblk --json -o +UUID >> $logfile 2>&1

tmp=$(lsblk --json | jq -r '.blockdevices[] | select(.type=="disk" and .mountpoint==null and .children==null) | .name')
if [[ -z "$tmp" ]]; then
	echo "No unallocated devices" >> $logfile
else
	device=/dev/$tmp
	echo "Found $device" >> $logfile
	contents=$(file -s $device | awk '{print $2}')
	if [[ "$contents" == "data" ]]; then
		echo '# --------------------------------' >> $logfile
		echo "device $device is raw" >> $logfile
		suffix="1"
		echo $tmp | grep -q nvm
		if (($?==0)); then
			suffix="p1"
		fi
		disk="$device""$suffix"

		echo "formatting $device" >> $logfile
		parted --script $device mklabel gpt >> $logfile 2>&1

		echo "creating partition on $device" >> $logfile
		parted --script --align optimal $device mkpart primary ext4 0% 100% >> $logfile 2>&1

		echo "trying mkfs.$fstype $disk" >> $logfile
		mkfs.$fstype $disk >> $logfile 2>&1
		if (($?!=0)); then
			sleep 5
			echo "retrying mkfs.$fstype $disk" >> $logfile
			mkfs.$fstype $disk >> $logfile 2>&1
		fi

		lsblk --json -o +UUID >> $logfile 2>&1

		echo '# --------------------------------' >> $logfile
		stub=$(basename $disk)
		echo "stub = $stub" >> $logfile
		/bin/cp -p /etc/fstab /var/tmp/userdata-etc-fstab

		echo "try to get UUID" >> $logfile
		uuid=$(lsblk --json -o +UUID | jq -r --arg name $stub '.blockdevices[] | select(.children != null) | .children[] | select(.type=="part" and .name==$name) | .uuid')
		if [[ "$uuid" == "null" ]]; then
			echo "trying again to get UUID" >> $logfile
			sleep 5
			uuid=$(lsblk --json -o +UUID | jq -r --arg name $stub '.blockdevices[] | select(.children != null) | .children[] | select(.type=="part" and .name==$name) | .uuid')
		fi
		if [[ "$uuid" == "null" ]]; then
			echo "putting device instead of UUID in /etc/fstab" >> $logfile
			echo "$disk $mountpoint $fstype defaults,nofail 0 2 # USERDATA" >> /etc/fstab
		else
			echo "Got the UUID and using it /etc/fstab" >> $logfile
			echo "UUID=$uuid $mountpoint $fstype defaults,nofail 0 2 # USERDATA" >> /etc/fstab
		fi
		mkdir -p $mountpoint
		chmod 777 $mountpoint
		cat /etc/fstab >> $logfile
		mount -a
	elif [[ "$contents" == "Linux" ]]; then
		echo "$device is already formatted" >> $logfile
	else
		echo "Could not determine contents of $device" >> $logfile
	fi
fi

lsblk --json -o +UUID >> $logfile
df >> $logfile

# --------------------------------

date >> $logfile
echo "Done" >> $logfile 2>&1

# --------------------------------

exit 0
