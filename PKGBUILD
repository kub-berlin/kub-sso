pkgname='libpam-kub-sso'
pkgver='0.0.0'
pkgdesc='Single sign-on for KuB'
arch=('all')
depends=(
	'adduser'
	'coreutils'
	'libpam-runtime'
	'libpam-script'
	'ecryptfs-utils'
	'python3'
	'python3-requests'
)

package() {
	install -D -m 644 pam-config "$pkgdir/usr/share/pam-configs/kub_sso"
	install -D -m 755 update-user.sh "$pkgdir/usr/bin/kub-update-user"
	install -D -m 755 pam-auth.py "$pkgdir/usr/lib/kub-sso/pam_script_auth"

	mkdir -p "$pkgdir/DEBIAN/"
	echo "#!/bin/sh" > "$pkgdir/DEBIAN/postinst"
	chmod 755 "$pkgdir/DEBIAN/postinst"
	echo 'pam-auth-update --package' >> "$pkgdir/DEBIAN/postinst"

	echo "#!/bin/sh" > "$pkgdir/DEBIAN/postrm"
	chmod 755 "$pkgdir/DEBIAN/postrm"
	echo 'pam-auth-update --package' >> "$pkgdir/DEBIAN/postrm"
}
