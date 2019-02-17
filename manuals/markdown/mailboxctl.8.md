MAILBOXCTL(8) - System Manager's Manual

# NAME

**mailboxctl** - control mail configuration

# SYNOPSIS

**mailboxctl**
\[**-h**]
\[**-f**&nbsp;*filename*]
\[**-p**&nbsp;*password*]
\[**-m**&nbsp;*modules*]
\[**-d**&nbsp;*domain*]
*command*

# DESCRIPTION

The
**mailboxctl**
script controls configuration of the archmailbox server.
It also is used to create and restore backups of the server.

# COMMANDS

**backupconfig**

> A backup of the selected modules is generated.
> The backup is encrypted using
> encpipe(1)
> with the password from the
> **-p**
> flag or the one entered during interactive use.
> The module list may be any of

> *dovecot*

> > configuration files in
> > */etc/dovecot*

> *rspamd*

> > configuration files in
> > */etc/rspamd/local.d*

> *smtpd*

> > configuration files in
> > */etc/smtpd*
> > along with the SQLite database of mail users

> *dkim*

> > dkim signing keys from
> > */var/lib/rspamd/dkim*

> *acme*

> > acme configuration files and certificates from
> > */var/lib/acme*

> If no module list is specified all modules are included in the backup.
> The module list is separated using a space between each module to be included.

**restoreconfig**

> restore a configuration generated using
> **backupconfig**.
> The module list must be the same as was used to create the backup.
> Importantly, if no module list is specified it will attempt to restore
> all modules that are supported and not all modules that are in the backup file.

> This command will erase all files in the paths for the specified module.
> It is recommended to save the current configuration first before using.

**gendkim**

> DKIM keys and configuration are generated for a new domain.
> Two DKIM keys are created.
> The first is a low security RSA key of bit length 1024 for legacy systems.
> The second is a high security ed25519 key for modern systems.
> This will set up two selectors and the configuration generated will sign
> email using both keys with different selectors.

> The generated configuration files will be located under a new directory
> *dkim\_domain.tld*
> in the current working path.

> While
> **installdkim**
> can install the configuration files and key, setting up DNS entries for
> the selectors is outside the scope of
> **mailboxctl**.
> The generated DNS entries will be located in
> *dkim\_domain.tld/domain.tld.dns*
> and will need to be added using whatever interface your DNS server provides.

**installdkim**

> A generated set of configuration files and DKIM keys will be installed in
> the current configuration.

> It will refuse to overwrite an existing configuration for a domain.
> The existing configuration will need to be removed from
> */etc/rspamd/local.d/dkim*
> and
> */var/lib/rspamd/dkim*
> if the selectors and DKIM keys are to changed from an existing configuration.

> Once the installation has been completed please remove the files from
> *dkim\_domain.tld*
> as they contain sensitive key material.

**gencert**

> Generates a Let's Encrypt certificate for the mail server
> and installs it under
> */var/lib/acme*.
> It also will use
> **deploycert**
> to deploy the certificate.
> A
> systemd(1)
> timer is set up during installation to automatically renew
> all acme.sh issued certificates when needed.

> This command will use the alpn stand-alone mode of acme.sh.
> No other service can be listening on port 443 or it will fail.
> Please refer to the acme.sh wiki at
> [https://github.com/Neilpang/acme.sh/wiki](https://github.com/Neilpang/acme.sh/wiki)
> for instructions on how to use other authentication methods
> including dns and integration with an existing web server.

**deploycert**

> Deploys a certificate for use with
> archmailbox(7)
> into
> */etc/acme*.

> Generally it is not needed to use this command
> separately from
> **gencert**,
> however it is needed when restoring from backup.
> It can also be used if port 443 is not available for acme.sh
> to use stand-alone mode.
> In this case the certificate can be generated with acme.sh
> with custom parameters, then deployed.
> Be aware that
> smtpd(8)
> only accepts RSA certificates if a custom issued one is to
> be used.

> The default configuration only allows for one certificate
> for the server.
> However, acme.sh does not have this limitation and you
> can safely issue more certificates by calling

> > acme.sh --home /var/lib/acme --issue ...

> as long as you do not deploy more than one
> using this command.
> Prior certificates are automatically backed up when new
> ones are deployed after renewal.
> The certificate backups are never rotated and are kept forever.

# FILES

*backup.tar.xz.encpipe*
is used as the default file for configuration backup and restore

# EXIT STATUS

The **mailboxctl** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

Linux 4.20.8-arch1-1-ARCH - February 16, 2019
