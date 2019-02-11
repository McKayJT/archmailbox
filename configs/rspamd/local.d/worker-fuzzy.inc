# Included from top-level .conf file

#backend = "redis";
enabled = no

# For sqlite stuff
#backend = "sqlite";
#hash_file = "${DBDIR}/fuzzy.db";

expire = 90d;
allow_update = ["localhost"];