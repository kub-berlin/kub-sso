# KuB single sign-on

When an organization grows, centralized account management becomes an important
issues. Unfortunately, the established ecosystem (Microsoft Active Directory,
LDAP, Kerberos, SSSD) suffers from a high degree of complexity. This project
attempts to provide similar features, while being much simpler. It consists of
two parts:

- A server that provides centralized account management using a simple config file.
- A PAM module that allows to use that server for login

The server doubles as a [Open ID Connect
Provider]https://openid.net/specs/openid-connect-core-1_0.html), so the same
accounts can also be used for web services.

The PAM module not does not actually performs authentication, but
creates/updates a local user account. This way, authentication still works when
the server is not available.

## Issues

-   Home directories are encrypted using ecryptfs. When the password is
    changed, the user needs to manually run `ecryptfs-rewrap-passphrase
    "$HOME/.ecryptfs/wrapped-passphrase"`.

-   Since the PAM module creates a local account, deleting a central account
    or changing its password currently has little effect because the clients
    can just continue to use the local account.

-   When a central account is deleted, local accounts and home directories are
    not deleted automatically.

-   In order to contact the server, the computer needs a network connection
    before login.
