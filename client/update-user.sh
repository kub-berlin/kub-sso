#!/bin/sh

set -e

create_user() {
	adduser --uid "$UID" --gecos "$FULLNAME,,," "$USER" --disabled-password --no-create-home
}

update_user() {
	usermod --groups "$GROUPS" "$USER"
	echo "$USER:$PASSWORD" | chpasswd
}

create_encrypted_home() {
	CRYPTDIR="/home/.ecryptfs/$USER/.Private"
	CONFIGDIR="/home/.ecryptfs/$USER/.ecryptfs"

	mkdir -p -m 700 "/home/$USER"
	mkdir -p -m 700 "$CRYPTDIR"
	mkdir -p -m 700 "$CONFIGDIR"

	ln -s "$CRYPTDIR" "/home/$USER/.Private"
	ln -s "$CONFIGDIR" "/home/$USER/.ecryptfs"
	ln -s /usr/share/ecryptfs-utils/ecryptfs-mount-private.txt "/home/$USER/README.txt"
	ln -s /usr/share/ecryptfs-utils/ecryptfs-mount-private.desktop "/home/$USER/Access-Your-Private-Data.desktop"
	chmod 500 "/home/$USER"
	chown -R "$USER:$USER" "/home/$USER"

	MOUNTPASS=$(od -x -N 16 --width=16 /dev/random | head -n 1 | sed "s/^0000000//" | sed "s/\s*//g")
	printf "%s" "$MOUNTPASS" | ecryptfs-add-passphrase --fnek - | sed 's/.*\[//;s/\].*//' > "$CONFIGDIR/Private.sig"
	printf "%s\n%s" "$MOUNTPASS" "$PASSWORD" | ecryptfs-wrap-passphrase "$CONFIGDIR/wrapped-passphrase" -
	chmod 400 "$CONFIGDIR/wrapped-passphrase"
	echo "/home/$USER" > "$CONFIGDIR/Private.mnt"
	touch "$CONFIGDIR/auto-mount"
	touch "$CONFIGDIR/auto-umount"
	chown -R "$USER:$USER" "/home/.ecryptfs/$USER"
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
