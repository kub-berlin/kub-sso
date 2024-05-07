#!/bin/sh

set -e

create_user() {
	adduser --uid "$UID" --gecos "$FULLNAME,,," "$USER" --disabled-password
}

update_user() {
	usermod --groups "$GROUPS" "$USER"
	echo "$USER:$PASSWORD" | chpasswd
}

if [ "$UID" -lt 1000 ]; then
	echo "UID too low" >&2
	exit 1
elif ! id "$USER" 2>&1 > /dev/null; then
	create_user
elif [ "$(id -u "$USER")" != "$UID" ]; then
	echo "UID does not match" >&2
	exit 1
fi

update_user
