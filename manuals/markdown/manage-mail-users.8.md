MANAGE-MAIL-USERS(8) - System Manager's Manual

# NAME

**manage-mail-users** - manage email user database

# SYNOPSIS

**manage-mail-users**
\[**-f**&nbsp;*database*]
\[**-d**&nbsp;*domain*]
\[**-u**&nbsp;*username*]
\[**-p**&nbsp;*password*]
*command*

# DESCRIPTION

**manage-mail-users**
is used to manage the SQLite database of mail users.

Usernames are in
`username@domain.tld`
format.

# COMMANDS

**create**

> create a new database

**add**

> add user to database

**delete**

> delete user from database

**password**

> update user password

**list**

> list all users

**addvirtual**

> add virtual domain

**delvirtual**

> delete virtual domain

**listvirtual**

> list virtual domains

# FILES

If
**-f**
is not passed, it will use
*/etc/smtpd/smtp.sqlite*
as the database to work on.

# EXIT STATUS

The **manage-mail-users** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# SECURITY CONSIDERATIONS

The
**-p**
option poses a security risk as any user on the system can see the password in the process list.
It is intended only for use during non-interactive setup.

Linux 4.20.8-arch1-1-ARCH - February 11, 2019
