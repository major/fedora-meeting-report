#!/usr/bin/env python
from bugzilla import Bugzilla
from collections import Counter
from datetime import datetime
from terminaltables import UnixTable


TABLES = [
        ('priority', 'Priority'),
        ('status', 'Status'),
        ('severity', 'Severity'),
        ('component', 'Component'),
        ('version', 'Distro Version')
        ]

VALID_STATUSES = ['NEW', 'ASSIGNED', 'MODIFIED', 'ON_QA']


def get_security_bugs():
    bz = Bugzilla(url='https://bugzilla.redhat.com/xmlrpc.cgi')
    query_data = {
        'keywords': 'SecurityTracking',
        'keywords_type': 'allwords',
        # 'component': 'cacti',
        # 'severity': 'high',
        'status': VALID_STATUSES,
    }
    bugs = bz.query(query_data)
    return bugs


def build_table(bugs, key, label, limit=None):
    # Find count of tickets based on our key
    frequency = Counter([getattr(x, key) for x in bugs])

    # How many tickets of each type are present?
    owned = {}
    for bug_key in frequency.keys():
        freq = Counter([('fst_owner' in x.status_whiteboard) for x in bugs
                       if getattr(x, key) == bug_key])
        owned[bug_key] = freq

    # Let's build rows for the table
    rows = [[label, 'Count', 'Owned', 'Unowned']]
    for bug_key, total in sorted(frequency.items(), key=lambda t: t[1],
                                 reverse=True):
        row = [
            bug_key,
            str(total),
            str(owned[bug_key][True]),
            str(owned[bug_key][False])
            ]
        rows.append(row)

    if limit is not None:
        rows = rows[0:limit]

    # Generate the table
    return UnixTable(table_data=rows,
                     title="Tickets by {0}".format(label)).table

# Gather data
bugs = get_security_bugs()

# Build Report
datestring = datetime.now().isoformat(' ')
print """
  __          _
 / _| ___  __| | ___  _ __ __ _
| |_ / _ \/ _` |/ _ \| '__/ _` |  Fedora Security Team Report
|  _|  __/ (_| | (_) | | | (_| |  Report date: {0}
|_|  \___|\__,_|\___/|_|  \__,_|
-------------------------------------------------------------------------------
""".format(datestring)

for table in TABLES:
    print build_table(bugs, table[0], table[1], 10)
    print
