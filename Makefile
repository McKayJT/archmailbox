CFLAGS ?= -O2 $(shell pkg-config --cflags libsodium)
LDFLAGS += $(shell pkg-config --libs libsodium)
prefix ?= /usr
datadir ?= $(prefix)/share
bindir ?= $(prefix)/bin
mandir ?= $(datadir)/man

src/treesutil:
	$(CC) $(CFLAGS) -o src/treesutil src/treesutil.c $(LDFLAGS)

all: src/treesutil

install: all
	mkdir -p $(DESTDIR)$(datadir)/archmailbox
	cp -r PKGBUILDs $(DESTDIR)$(datadir)/archmailbox
	cp -r configs $(DESTDIR)$(datadir)/archmailbox
	install -Dm755 src/treesutil \
		$(DESTDIR)$(bindir)/treesutil
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
	install -Dm644 manuals/archmailbox-install.8 \
		$(DESTDIR)$(mandir)/man8/archmailbox-install.8
	install -Dm644 manuals/archmailbox.7 \
		$(DESTDIR)$(mandir)/man7/archmailbox.7

.PHONY: install all
