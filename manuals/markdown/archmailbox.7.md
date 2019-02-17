ARCHMAILBOX(7) - Miscellaneous Information Manual

# NAME

**archmailbox** - archmailbox project

# DESCRIPTION

The
**archmailbox**
provides a number of different programs and
configurations to allow for easy mail server setup.
This manual page documents the programs and the
configuration that is used by default.

# BASIC LAYOUT

**archmailbox**
uses
smtpd(8)
for mail delivery and receipt.
Incoming mail is filtered using
rspamd(8)
using the
rspamc(1)
command before being delivered to
dovecot(1)
for delivery to the local mail store.
Outgoing mail is received by
smtpd(8)
which then forwards the mail to
**pyrelay-rspamd**
which uses
rspamd(8)
to DKIM sign the messages.
**pyrelay-rspamd**
Then sends the messages back to
smtpd(8)
on a trusted port which then relays the mail to the destination mail server.

Mail is stored locally in the maildir format compressed using
xz(1)
compression.
It is subject to a quota default quota of 15GB per user and an
message size limit of 100MB.

Mail users are virtual and are stored in the
*/etc/smtpd/smtp.sqlite*
database.
The passwords are hashed using the Argon2 password hashing scheme.

acme.sh is used to generate and renew Let's Encrypt tls
certificates.
The configuration files are set up under
*/var/lib/acme*
and the installed certificates used by the server are located in
*/etc/acme*

The
**gencert**
command will use stand-alone mode using alpn.
This means that no other service can be listening on port 443 of the server.
If you already have a web server set up, acme.sh can be used to issue
the certificate and installed using
**deploycert**.

# COMMANDS

**archmailbox**
comes with a number of scripts to ease administration of the
server.

archmailbox-install(8)

> used to install the packages and initial configuration files

mailboxctl(8)

> used to manage the configuration, as well as backup and restore
> the server.

manage-mail-users(8)

> used to manage the SQLite user database.

# SECURITY

**archmailbox**
attempts to be secure by default.
dovecot(1)
will deliver new mail using the
`vmail`
user.
This user is also given access to communicate with
rspamd(8)
via unix domain socket.
The
dovecot(1)
authentication process uses the smtpd group to allow access to the
user configuration database.

The \_rspamd user has control over DKIM keys stored in
*/var/lib/rspamd/dkim*.
No other user is given access to the keys.

# SEE ALSO

dovecot(1),
archmailbox-install(8),
mailboxctl(8),
manage-mail-users(8),
rspamd(8),
smtpd(8)

Linux 4.20.8-arch1-1-ARCH - February 16, 2019
