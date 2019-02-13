#!/bin/sh
exec /usr/lib/dovecot/dovecot-lda "${1}" "${2}" "${3}" "${4}" -e
# we don't care about the exit status in this case
exit 0
