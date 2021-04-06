import sys
from thirdparty import urllib3

# This code exists for backwards compatibility reasons.
# I don't like it either. Just look the other way. :)
# urllib3 = "/opt/tools/scan/vulmap/thirdparty/urllib3"
for package in ('urllib3', 'idna', 'chardet'):
    locals()[package] = __import__(package)
    # This traversal is apparently necessary such that the identities are
    # preserved (requests.packages.urllib3.* is urllib3.*)
    for mod in list(sys.modules):
        if mod == package or mod.startswith(package + '.'):
            sys.modules['requests.packages.' + mod] = sys.modules[mod]

# Kinda cool, though, right?
