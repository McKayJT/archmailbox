ARCHMAILBOX-INSTALL(8) - System Manager's Manual

# NAME

**archmailbox-install** - initial archmailbox installation

# SYNOPSIS

**archmailbox-install**
*installpkgs*&nbsp;|&nbsp;*installconfigs*

# DESCRIPTION

**archmailbox-install**
installs the initial configuration and packages for the
archmailbox(7)
project.

**installpkgs**
must be run as a non-root user with sudo permissions.
**installconfigs**
must be run as root.

# ENVIRONMENT

`HOSTNAME`

> fqdn of current host

`EGRESS`

> network interface to listen for incoming mail

# EXIT STATUS

The **archmailbox-install** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# EXAMPLES

	$ archmailbox-install installpkgs

	# archmailbox-install installconfigs

Linux 4.20.10-arch1-1-ARCH - February 16 2019
