TREESUTIL(1) - General Commands Manual

# NAME

**treesutil** - trees plugin helper

# SYNOPSIS

**treesutil**
\[**-v**]
**-c**&nbsp;|&nbsp;**-p**&nbsp;|&nbsp;**-s**  
**treesutil**
**-d**
**-i**&nbsp;*input&#160;file*
**-o**&nbsp;*output&#160;file*  
**treesutil**
**-h**

# DESCRIPTION

The
**treesutil**
utility helps create and manage the key data used by the trees
plugin for
dovecot(1).
It also can create ed25519 key pairs.
In general it takes null delimited input from standard input
and writes null delimited input to standard output.

The arguments are as follows:

**-v**

> Debugging output is written to standard error.
> This option is insecure as it will write private key data
> and should only be used when debugging the program.

**-c**

> Create a user.
> Takes as input the password that is to be used from the user.
> Prints the public key, salt, nonce, and locked private key to
> standard output delimited by null characters.

**-p**

> Change a password.
> Takes an input the public key, salt, nonce, locked private key
> in hex format, the old password and the new password.
> These are all delimited with null characters.
> The output is the same as the
> **-c**
> flag.

**-d**

> Decrypt file.
> Takes an input the public key, salt, nonce, locked private key
> in hex format, and the password.
> Flags
> **-i**
> and
> **-o**
> are mandatory using this function.

**-s**

> Create ed25519 key pair.
> Takes no inputs.
> Output is base64 encoded seed string and public key separated
> with a space with a newline at the end.

**-h**

> Print short help message.

# EXIT STATUS

The **treesutil** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# EXAMPLES

Create a new user entry, then change the password

	$ echo -n "password" | treesutil -c >user.data
	$ echo -en "password\0newpassword" >>user.data
	$ treesutil -p <user.data >newuser.data

Linux 4.20.10-arch1-1-ARCH - February 19, 2019
