#!/bin/sh
exec /usr/bin/rspamc -h /run/rspamd/controller.sock -d "${1}" learn_ham
# we don't care about the exit status in this case
exit 0
