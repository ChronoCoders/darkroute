"""Split a PostgreSQL connection URL for the test database setup script.

Only two questions are asked of it: which database the url names, and what the
same url looks like pointed at the maintenance database. Creating a database
cannot be done from a connection to that database, so the second form is what the
CREATE DATABASE runs against.

Prints nothing but the requested piece, so the caller can capture it directly. A
password in the url is never printed.
"""

import sys
import urllib.parse

MAINTENANCE_DB = "postgres"


def split(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql"):
        raise ValueError("not a postgres url, scheme is %r" % parts.scheme)
    name = parts.path.lstrip("/")
    if not name:
        raise ValueError("the url names no database")
    return parts, name


def rebuild(parts, dbname):
    """Swap the database name, keeping an empty authority as the triple slash form.

    urlunsplit collapses an empty netloc, turning postgres:///db into postgres:/db,
    which is not the same url: the socket form needs the authority present and
    empty. So that case is assembled by hand.
    """
    swapped = parts._replace(path="/" + dbname)
    if swapped.netloc:
        return urllib.parse.urlunsplit(swapped)
    query = "?" + swapped.query if swapped.query else ""
    return "%s://%s%s" % (swapped.scheme, swapped.path, query)


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("dbname", "maintenance"):
        print("usage: dburl.py <url> dbname|maintenance", file=sys.stderr)
        return 2
    try:
        parts, name = split(sys.argv[1])
    except ValueError as exc:
        print("TEST_DATABASE_URL is unusable: %s" % exc, file=sys.stderr)
        return 1
    if sys.argv[2] == "dbname":
        print(name)
    else:
        print(rebuild(parts, MAINTENANCE_DB))
    return 0


if __name__ == "__main__":
    sys.exit(main())
