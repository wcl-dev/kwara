"""Test fixtures: a local HTTP origin plus the HTML / ads.txt samples.

Nothing here imports kwara. The collection layer (scanner, cloaking, ads.txt,
snapshots) is the part of the tool that talks to the network, and it can only
be tested honestly against a server that behaves like a hostile one —
redirect chains, WAF challenges, slow responses, bodies that change with the
query string. `server.TestSite` is that server, bound to 127.0.0.1 on a
kernel-assigned port.
"""
