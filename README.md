# KuB single sign-on

When an organization grows, centralized account management becomes an important
issues. Unfortunately, the established ecosystem (Microsoft Active Directory,
LDAP, Kerberos, SSSD) suffers from a high degree of complexity. This project
attempts to provide similar features, while being much simpler. It consists of
three parts:

- A server that provides centralized account management using a simple config file.
- A PAM module that allows to use that server for login
- A shell script that creates/updates users

The server doubles as a [Open ID Connect
Provider](https://openid.net/specs/openid-connect-core-1_0.html), so the same
accounts can also be used for web services.

The PAM module does not actually performs authentication, but creates/updates a
local user account. This way, authentication still works when the server is not
available.

## Issues

-   The authentication server is available on the network, so attacking it is
    much simpler than attacking local user accounts.

-   Home directories are encrypted using ecryptfs. When the password is
    changed, the user needs to manually run `ecryptfs-rewrap-passphrase
    "$HOME/.ecryptfs/wrapped-passphrase"`.

-   In order to contact the server, the computer needs a network connection
    before login.

## Threat model

We assume that an attacker has unlimited (non-root) access to a client device
and the network. Possible attacks include:

-   Denial of service by blocking access to the authentication server
    -   Mitigation (PAM): Local accounts are available for 7 days
-   Denial of service by triggering DDoS protection
-   Login with outdated password if local account has not yet been updated (PAM)
    -   Mitigation: Local accounts expire after 7 days
-   Changes to local account are overwritten by SSO (PAM)
    -   Mitigation: Exclude local accounts from SSO by adding them to `BLOCKED_USERS`
-   Gain access by replacing the authentication server
    -   Mitigation: Use a valid TLS certficate on the authentication server
-   Gain superuser access by replacing the authentication server
    -   Mitigation (PAM): Some users and groups are blocked from SSO (root, sudo, wheel)
-   Gain access with incorrect password due to incorrect (or outdated) implementation of authentication backends
-   Enumerate users
    -   Mitigation: The Server gives the same response on all errors
-   Brute force passwords
