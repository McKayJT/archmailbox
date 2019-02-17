#!/usr/bin/env sh

#domain keyfile certfile cafile fullchain
mailbox_deploy() {
  _cdomain="$1"
  _ckey="$2"
  _ccert="$3"
  _cca="$4"
  _cfullchain="$5"

  _debug _cdomain "$_cdomain"
  _debug _ckey "$_ckey"
  _debug _ccert "$_ccert"
  _debug _cca "$_cca"
  _debug _cfullchain "$_cfullchain"

  _mailbox_home="/etc/acme"

  if [ ! -d "$_mailbox_home" ]; then
    _debug "creating $_mailbox_home"
    _err "$_mailbox_home is missing"
  fi

  # backup certs
  if [ ! -d "$_mailbox_home/backup" ]; then
    _debug "creating $_mailbox_home/backup"
    mkdir "$_mailbox_home/backup"
    chmod 700 "$_mailbox_home/backup"
  fi
  if [ -r "$_mailbox_home/private.key" ] || [ -r "$_mailbox_home/fullchain.cer" ]; then
    _mailbox_backup_dir="$_mailbox_home/backup/$(date +%F.%H.%M.%S)"
    _debug "creating $_mailbox_backup_dir"
    mkdir "$_mailbox_backup_dir"
    chmod 700 "$_mailbox_backup_dir"
  fi
  if [ -r "$_mailbox_home/private.key" ]; then
    _debug "copying private key to backup"
    cp "$_mailbox_home/private.key" "$_mailbox_backup_dir/"
  fi
  if [ -r "$_mailbox_home/fullchain.cer" ]; then
    _debug "copying fullchain to backup"
    cp "$_mailbox_home/fullchain.cer" "$_mailbox_backup_dir/"
  fi

  # install certificates
  _debug "deploy keys"
  cat "$_ckey" >"$_mailbox_home/private.key"
  cat "$_cfullchain" >"$_mailbox_home/fullchain.cer"

  # restart daemons
  _debug "restart daemons"
  if systemctl is-enabled dovecot; then
    systemctl restart dovecot
  fi
  if systemctl is-enabled smtpd; then
    systemctl restart smtpd
  fi

  return 0
}

# vim: ts=2:sw=2:et
