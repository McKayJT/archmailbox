# Arch Linux EZ Mail Server

Taking all the examples of a mail server configuration from the
internet and putting them together so you don't need to.

# Project Goals

* 'Batteries included' mail server
* Secure by default
* Scripts to manage, backup, and restore configuration
* Spam filtering
* DKIM signatures on outbound mail

# Project Non-goals

* Highly scalable configuration
* Many knobs and levels for mail configuration
* Automation friendly scripts for user management

# Why?

I wanted to set up a personal mail server for a vanity domain and
while putting all the bits together realized that there wasn't anything
that 'just worked' for simple configurations. There were many configuration
examples but putting all of the bits together took time and effort.

Why have other people go through the same effort and reading that I did when
all they want is a simple and secure configuration for a personal email server?
It also serves as a reason for me to write scripts to help manage my server and
simplify my future efforts.

# Project status

## Working items

* Script to manage database of email users and domains
* Script to backup and restore configuration
* dovecot, rspamd, pyrelay-rspamd, and OpenSMTPD configuration files
* Automated build and install of required packages
* acme.sh configuration and installation
* Installation of initial configuration
* PKGBUILDs for all the projects needed for the server
* Installation of initial configuration

## Semi-working items

* None!

## Non-working items

* Backup and restore of email
  * Maybe this gets skipped? Too complex for a one-size-fits-all approach.

# Software Used

A brief overview of the bits and pieces that come together.

* [OpenSMTPD](https://www.opensmtpd.org) - Core mail daemon providing secure mail services. 
  * This has some limitations
  * Mail filtering support is not there yet, which means that we need to use
rspamc and pyrelay-rspamd to filter for spam and DKIM sign messages
  * Only RSA certificates are supported. RSA in 2019 makes me have a sad.
  * Upstream has gone full LibreSSL which means that the Arch Linux package
has been out of date for months. I 'fix' this using static dependencies.
  * Normally stores passwords in bcrypt format. Included in the PKGBUILD is a patch
for argon2 support.
* OpenSMTPD-extras - SQLite table support
  * This incredibly useful package doesn't seem to be documented anywhere
on the OpenSMTPD site outside of a tarball in the downloads folder.
  * Using a SQLite table back-end provides much better integration with dovecot
* Rspamd - spam filtering and DKIM signing
  * Good spam filtering out of the box
  * Upstream has merged my support for ed25519 signatures per
[RFC 8463](https://www.rfc-editor.org/rfc/rfc8463.txt). This means we can use
a somewhat small RSA key to placate servers that only support the older keys
while still providing a high-security signature.
* pyrelay-rspamd - proxy to add DKIM signatures via Rspamd
  * replaces DKIMproxy that other OpenSMTPD setups use
  * low-effort python script that will be obsolete when OpenSMTPD
releases the next version with native filter support.
* encpipe
  * Used for easy encryption of backups. Naively supports streaming encryption
  * Undecided: should I ship the original gimli based version, or my version
that uses libsodium?
* knot-resolver
  * Rspamd generates many DNS requests, also VPS providers are not known for
making a good DNS server available.
