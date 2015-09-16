#!/usr/bin/env python
from bugzilla import Bugzilla
from collections import Counter
from datetime import datetime, date
from terminaltables import UnixTable
from sqlalchemy import create_engine, func, select, Table, Column, Integer, String, Date, MetaData

engine = create_engine('sqlite:///sqlite3.db', echo=False)
metadata = MetaData()

bugcounts = Table('bugcounts', metadata,
    Column('reportdate', Date(), primary_key=True),
    Column('bugtable', String(16), primary_key=True),
    Column('category', String(32), primary_key=True),
    Column('owned', Integer),
    Column('unowned', Integer))

metadata.create_all(engine)
conn = engine.connect()

TABLES = [
        ('priority', 'Priority'),
        ('status', 'Status'),
        ('severity', 'Severity'),
        ('component', 'Component'),
        ('version', 'Distro Version')
        ]

VALID_STATUSES = ['NEW', 'ASSIGNED', 'MODIFIED', 'ON_QA']

# check if db contains current date - if yes do not collect data
curdate = date.today()
collect_data = False
sel = select([func.count(bugcounts.c.reportdate).label('reportdates')]).where(bugcounts.c.reportdate == curdate)
cnt = conn.execute(sel).fetchone()[0]
if (cnt == 0):
    collect_data = True

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

    headers = [[label, 'Count', 'Owned', 'Unowned']]
    # Let's build rows for the table
    rows = []
    tupels = []
    for bug_key, total in sorted(frequency.items(), key=lambda t: t[1],
                                 reverse=True):
        row = [
            bug_key,
            str(total),
            str(owned[bug_key][True]),
            str(owned[bug_key][False])
            ]
        rows.append(row)
        if collect_data:
            dbtupel = dict(zip(['reportdate', 'bugtable', 'category', 'owned', 'unowned'],
                            [curdate, key, bug_key, owned[bug_key][True], owned[bug_key][False]]))
            tupels.append(dbtupel)

    if limit is not None:
        rows = rows[0:limit]

    if collect_data:
        conn.execute(bugcounts.insert(), tupels)

    # Generate the table
    return UnixTable(table_data=headers+rows,
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
