#!/usr/bin/env python3
"""
Enable the Recycle Bin optional feature
https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
python3 enablerecylcebin /var/lib/samba/private/sam.ldb
"""
import optparse
import sys

# Find right directory when running from source tree
sys.path.insert(0, "bin/python")

import samba
from samba import getopt as options, Ldb
from ldb import SCOPE_BASE
import sys
import ldb
from samba.auth import system_session

parser = optparse.OptionParser("enablerecyclebin <URL>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option_group(options.VersionOptions(parser))

opts, args = parser.parse_args()
opts.dump_all = True

if len(args) != 1:
    parser.print_usage()
    sys.exit(1)

url = args[0]

lp_ctx = sambaopts.get_loadparm()

creds = credopts.get_credentials(lp_ctx)
sam_ldb = Ldb(url, session_info=system_session(), credentials=creds, lp=lp_ctx)

# get the rootDSE
res = sam_ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["configurationNamingContext"])
rootDse = res[0]

configbase=rootDse["configurationNamingContext"]

# enable the feature
msg = ldb.Message()
msg.dn = ldb.Dn(sam_ldb, "")
msg["enableOptionalFeature"] = ldb.MessageElement(
     "CN=Partitions," +  str(configbase) + ":766ddcd8-acd0-445e-f3b9-a7f9b6744f2a",
     ldb.FLAG_MOD_ADD, "enableOptionalFeature")
res = sam_ldb.modify(msg)

print("Recycle Bin feature enabled")
