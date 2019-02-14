prefix ?= /usr
datadir ?= $(prefix)/share
bindir ?= $(prefix)/bin
mandir ?= $(datadir)/man

install:
	mkdir -p $(DESTDIR)$(datadir)/archmailbox
	cp -r PKGBUILDs $(DESTDIR)$(datadir)/archmailbox
	cp -r configs $(DESTDIR)$(datadir)/archmailbox
	install -Dm755 scripts/eddsatool \
		$(DESTDIR)$(bindir)/eddsatool
	install -Dm755 scripts/mailboxctl \
		$(DESTDIR)$(bindir)/mailboxctl
	install -Dm755 scripts/manage-mail-users \
		$(DESTDIR)$(bindir)/manage-mail-users
	install -Dm755 scripts/archmailbox-install \
		$(DESTDIR)$(bindir)/archmailbox-install
	install -Dm644 manuals/mailboxctl.8 \
		$(DESTDIR)$(mandir)/man8/mailboxctl.8
	install -Dm644 manuals/manage-mail-users.8 \
		$(DESTDIR)$(mandir)/man8/manage-mail-users.8

.PHONY: install
