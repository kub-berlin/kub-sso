#!/bin/sh

set -e

CRYPTDIR="/home/.ecryptfs/$USER/.Private"
CONFIGDIR="/home/.ecryptfs/$USER/.ecryptfs"

create_user() {
	adduser --uid "$UID" --gecos "$FULLNAME,,," "$USER" --disabled-password --no-create-home
}

update_user() {
	usermod --groups "$GROUPS" --expiredate "$(date -d +7days +%Y-%m-%d)" "$USER"
	echo "$USER:$PASSWORD" | chpasswd
}

create_encrypted_home() {
	mkdir -p -m 700 "/home/$USER"
	mkdir -p -m 700 "$CRYPTDIR"
	mkdir -p -m 700 "$CONFIGDIR"

	ln -s "$CRYPTDIR" "/home/$USER/.Private"
	ln -s "$CONFIGDIR" "/home/$USER/.ecryptfs"
	ln -s /usr/share/ecryptfs-utils/ecryptfs-mount-private.txt "/home/$USER/README.txt"
	ln -s /usr/share/ecryptfs-utils/ecryptfs-mount-private.desktop "/home/$USER/Access-Your-Private-Data.desktop"
	chmod 500 "/home/$USER"
	chown -R "$USER:$USER" "/home/$USER"

	echo "/home/$USER" > "$CONFIGDIR/Private.mnt"
	touch "$CONFIGDIR/auto-mount"
	touch "$CONFIGDIR/auto-umount"
	chown -R "$USER:$USER" "/home/.ecryptfs/$USER"
}

update_encrypted_home() {
	if [ -f "$CONFIGDIR/wrapped-passphrase" ]; then
		chmod 600 "$CONFIGDIR/wrapped-passphrase"
	fi
	printf "%s" "$ECRYPTFS_PASSPHRASE" | ecryptfs-add-passphrase --fnek - | sed 's/.*\[//;s/\].*//' > "$CONFIGDIR/Private.sig"
	printf "%s\n%s" "$ECRYPTFS_PASSPHRASE" "$PASSWORD" | ecryptfs-wrap-passphrase "$CONFIGDIR/wrapped-passphrase" -
	chmod 400 "$CONFIGDIR/wrapped-passphrase"
	chown -R "$USER:$USER" "$CONFIGDIR"
}

create_netzordner_mountpoint() {
	mkdir -p "/media/$USER/int"
	mkdir -p "/media/$USER/netzordner"
	chmod 750 "/media/$USER"
	setfacl -m "u:$USER:rx" "/media/$USER"
	chown "$USER:$USER" "/media/$USER/int"
}

if [ "$UID" -lt 1000 ]; then
	echo "UID too low" >&2
	exit 1
elif ! id "$USER" 2>&1 > /dev/null; then
	create_user
	create_encrypted_home
	create_netzordner_mountpoint
elif [ "$(id -u "$USER")" != "$UID" ]; then
	echo "UID does not match" >&2
	exit 1
fi

update_user
update_encrypted_home
