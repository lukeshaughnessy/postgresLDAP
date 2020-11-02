#! /usr/bin/env python
"""
psqlusr - User management client for LDAP(FreeIPA)-PostgreSQL.

Copyright (C) 2019 Fraugster Services GmBH.

All rights reserved.

"""

import os
import sys
import logging
import argparse
import time
import yaml
from models import ldap, postgres

PROGRAM_NAME = 'psqlusr'

with open(r'.gitlab-ci.yml') as file:
    # Program version is coupled to the image release version.
    # Always change it to reflect the changes made to psqlusr :)

    VERSION = yaml.load(file,
                        Loader=yaml.FullLoader).get("variables").get("PSQLUSR_IMAGE_VERSION")

NODE_EXPORTER_FILE = "/var/lib/node_exporter/textfile_collector/psqlusr_client.prom"
LOG_LEVEL = logging.INFO


def main(args):
    """
    Main command line function
    """
    log_conf = {"format": '%(asctime)s - %(levelname)s - %(message)s',
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "level": LOG_LEVEL}

    perms = {"RO": 1, "RW": 2, "SU": 3}
    logging.basicConfig(**log_conf)

    node_exporter_msg = "psqlusr_client_success{hostname=\"" + args.hostname + "\"} %d\n"

    try:
        psqlusr_ldap_obj = ldap.psqlusrLdap(args=args,
                                        perms=perms)
        psqlusr_pg_obj = postgres.psqlusrPostgres(args=args,
                                              perms=perms)

        psqlusr_ldap_obj.psqlusr_ldap_init(args.default_rules)
        psqlusr_pg_obj.psqlusr_pg_init()

        role_maps_prev = {}
        while True:
            role_maps_next = psqlusr_ldap_obj.psqlusr_ldap_main()
            psqlusr_pg_obj.psqlusr_pg_main(role_map_diff(role_maps_prev, role_maps_next))

            with open(NODE_EXPORTER_FILE, 'w') as node_exporter_file:
                node_exporter_file.write(node_exporter_msg % 1)

            role_maps_prev = role_maps_next
            time.sleep(int(args.delay))

    except SystemError:
        with open(NODE_EXPORTER_FILE, 'w') as node_exporter_file:
            node_exporter_file.write(node_exporter_msg % 0)
        sys.exit(1)


def role_map_diff(role_map_prev, role_map_next):
    """
    Filters for updates by determining the diff between the incoming and the last fetched role_map
    :param role_map_prev: last fetched role mappings. Example:
    {'psqlusrdb_1': {'psqlusruser_1': 'RW', 'psqlusruser_2': 'RO', 'psqlusruser_3': 'RW'},
     'psqlusrdb_2': {'psqlusruser_2': 'SU'} }

    :param role_map_next: incoming role mappings. Example:
    {'psqlusrdb_1': {'psqlusruser_1': 'RW', 'psqlusruser_2': 'RW', 'psqlusruser_3': 'RW'},
     'psqlusrdb_2': {'psqlusruser_2': 'RO'},
     'psqlusrdb_3': {'psqlusruser_4': 'RO'}}

    :return:
    {'psqlusrdb_1': {'update': {'psqlusruser_2': 'RW'}, 'skip': ['psqlusruser_1', 'psqlusruser_3']},
    'psqlusrdb_2': {'update': {'psqlusruser_2': 'RO'}, 'skip': []},
    'psqlusrdb_3': {'update': {'psqlusruser_4': 'RO'}, 'skip': []}}
    """

    role_map_sort = {}
    for database in role_map_next:
        if role_map_prev.get(database):
            role_map_sort[database] = {"update": {k: v for k, v in role_map_next[database].items()
                                                  if (k in role_map_prev[database]
                                                      and v != role_map_prev[database][k])
                                                  or k not in role_map_prev[database]},

                                       "skip": [k for k, v in role_map_next[database].items()
                                                if k in role_map_prev[database]
                                                and v == role_map_prev[database][k]]}
        else:
            role_map_sort[database] = {"update": role_map_next[database], "skip": []}
    return role_map_sort


def arg_parser():
    """Parse command line ARGS and commands."""

    parser = argparse.ArgumentParser(
        description='LDAP-Postgres user management.'
    )

    parser.add_argument('--delay',
                        help='Frequency of update checks',
                        dest='delay',
                        default=os.getenv("PSQLUSR_DELAY", "120"))

    parser.add_argument('--default-rules',
                        help='Default rules to initialise the hbac with',
                        nargs="*",
                        dest='default_rules',
                        default=[])

    parser.add_argument('--ldaphost',
                        help='Set URI of the LDAP server',
                        dest='ldaphost',
                        default=os.getenv("PSQLUSR_LDAPHOST"))

    parser.add_argument('--ldapport',
                        help='Set the listening port of the LDAP server',
                        dest='ldapport',
                        default=os.getenv("PSQLUSR_LDAPPORT"))

    parser.add_argument('--psqlservice',
                        help='Set the LDAP service to filter for',
                        dest='psqlservice',
                        default=os.getenv("PSQLUSR_PSQLSERVICE"))

    parser.add_argument('--hostname',
                        help='Set the LDAP service to filter for',
                        dest='hostname',
                        default=os.getenv("PSQLUSR_HOSTNAME"))

    parser.add_argument('--ldappassword',
                        help='Set the password for authenticating '
                             'and binding to the LDAP server',
                        dest='ldappassword',
                        default=os.getenv("PSQLUSR_LDAPPASSWORD"))

    parser.add_argument('--ldapuser',
                        help='Set the user for authenticating '
                             'and binding to the LDAP server',
                        dest='ldapuser',
                        default=os.getenv("PSQLUSR_LDAPUSER", "Directory Manager"))

    parser.add_argument('--pgadminuser',
                        help='Set the admin username for authenticating '
                             'to Postgres',
                        dest='pgadminuser',
                        default=os.getenv("PSQLUSR_PGADMINUSER"))

    parser.add_argument('--pgadminpassword',
                        help='Set the password for authenticating '
                             'to Postgres',
                        dest='pgadminpassword',
                        default=os.getenv("PSQLUSR_PGADMINPASSWORD"))

    parser.add_argument('--pgadmindb',
                        help='Set the admin database in Postgres to connect to.',
                        dest='pgadmindb',
                        default=os.getenv("PSQLUSR_PGADMINDB", "postgres"))

    parser.add_argument('--pghost',
                        help='Set the postgres host to connect to.',
                        dest='pghost',
                        default=os.getenv("PSQLUSR_PGHOST", "localhost"))

    parser.add_argument('--version',
                        action='version',
                        version='%(prog)s v {v}'.format(v=VERSION),
                        help='Show the version numbers and exit')

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    main(arg_parser())
