# Included from top-level .conf file
dns {
    nameserver = [ "[::1]:53" ]
    timeout = 3s;
    sockets = 16;
    retransmits = 5;
}

# Timeout for messages processing (must be larger than any internal timeout used)
task_timeout = 10s;
