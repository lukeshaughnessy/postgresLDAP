"""
psqlusr Postgres module
"""
import logging
import psycopg2


class psqlusrPostgres:
    """
    Handles connections to the postgres database(s)
    """

    def __init__(self, args, perms):
        self.user = args.pgadminuser
        self.host = args.pghost
        self.password = args.pgadminpassword
        self.postgres_admin_db = args.pgadmindb
        self.available_databases = []
        self.available_users = []
        self.perm_ranking = perms

    def psqlusr_pg_init(self):
        """
        Create role/group, if it doesn't exist, for all users to be managed by psqlusr.

        """
        try:
            pg_conn = self.pg_connect(self.postgres_admin_db)
            pg_cursor = pg_conn.cursor()

            pg_cursor.execute("DO $$ "
                              "BEGIN "
                              "CREATE ROLE {u}; "
                              "EXCEPTION WHEN duplicate_object THEN "
                              "RAISE NOTICE 'psqlusr: User already exists, skipping creation'; "
                              "END "
                              "$$;".format(u="psqlusr_managed"))
            pg_conn.commit()
            pg_cursor.close()
            pg_conn.close()

        except psycopg2.Error as err:
            logging.error(err)
            logging.error("Initial connection to Postgres failed, check admin's attributes")
            raise SystemError

    def psqlusr_pg_main(self, role_maps):
        """
        Fetches the available databases and users; calls apply_roles
        """
        try:
            pg_conn = self.pg_connect(self.postgres_admin_db)
            pg_cursor = pg_conn.cursor()

            pg_cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            pg_conn.commit()
            self.available_databases = [row_tuple[0] for row_tuple in pg_cursor.fetchall()]

            pg_cursor.execute("SELECT usename FROM pg_user u "
                              "INNER JOIN pg_catalog.pg_auth_members m ON (m.member = u.usesysid) "
                              "INNER JOIN pg_roles r ON (m.roleid = r.oid) "
                              "where r.rolname='psqlusr_managed';")
            pg_conn.commit()
            self.available_users = [row_tuple[0] for row_tuple in pg_cursor.fetchall()]
            pg_conn.close()

        except psycopg2.Error as err:
            logging.error(err)
            logging.error("Connection to Postgres failed, check admin's attributes")
            raise SystemError

        self.apply_roles(role_maps)

    def apply_roles(self, role_maps):
        """
        Apply roles, as fetched from LDAP.
        """
        perm_funcs = dict(zip(self.perm_ranking,
                              [self.perm_ro, self.perm_rw, self.perm_su]))

        for dbname in self.available_databases:
            wildcard_perms = role_maps["*"].copy()
            if dbname in role_maps:
                duplicate_users = role_maps[dbname]["update"].keys() & \
                                  wildcard_perms["update"].keys()
                for user in duplicate_users:
                    if self.perm_ranking[role_maps[dbname][user]["update"]] < \
                            self.perm_ranking[wildcard_perms[user]]:
                        del wildcard_perms["update"][user]

                role_maps[dbname]["update"].update(wildcard_perms["update"])
                role_maps[dbname]["skip"].extend(u for u in wildcard_perms["skip"]
                                                 if u not in role_maps[dbname]["skip"])
            else:
                role_maps[dbname] = wildcard_perms

            try:

                pg_conn = self.pg_connect(dbname)
                pg_cursor = pg_conn.cursor()
                allowed_users = role_maps[dbname]["skip"].copy()

                for usr, perm in role_maps[dbname]["update"].items():
                    try:

                        self.create_user(usr, pg_cursor)
                        self.purge_perms(usr,
                                         pg_cursor,
                                         dbname == self.postgres_admin_db)
                        perm_funcs.get(perm)(usr, pg_cursor)
                        allowed_users.append(usr)

                    except psycopg2.Error as err:
                        logging.error(err)
                        logging.error(msg="Permissions failed for database: "
                                          "%s and user: %s" % (dbname, usr))
                        raise SystemError

                for usr in self.available_users:
                    if usr not in allowed_users:
                        self.purge_perms(usr,
                                         pg_cursor,
                                         is_su=dbname == self.postgres_admin_db)
                pg_conn.commit()
                pg_cursor.close()
                pg_conn.close()

                logging.info(msg="Permissions successfully applied for database: "
                                 "%s. Updated: %d, Unchanged %d" %
                             (dbname,
                              len(role_maps[dbname]["update"]),
                              len(role_maps[dbname]["skip"])))

            except psycopg2.Error as err:
                logging.error(err)
                logging.error(msg="Permissions failed for database: %s" % dbname)
                continue

    @staticmethod
    def perm_ro(user, pg_cursor):
        """
        Defines, SQL statements for read-only permissions.
        """

        pg_cursor.execute("GRANT USAGE, SELECT "
                          "ON ALL SEQUENCES IN SCHEMA public "
                          "TO {u};".format(u=user))

        pg_cursor.execute("GRANT SELECT "
                          "ON ALL TABLES IN SCHEMA public "
                          "TO {u};".format(u=user))
        pg_cursor.connection.commit()

    @staticmethod
    def perm_rw(user, pg_cursor):
        """
        Defines, SQL statements for read-write permissions.
        """

        pg_cursor.execute("GRANT CREATE "
                          "ON SCHEMA public "
                          "TO {u};".format(u=user))

        pg_cursor.execute("GRANT USAGE, SELECT "
                          "ON ALL SEQUENCES IN SCHEMA public "
                          "TO {u};".format(u=user))

        pg_cursor.execute("GRANT ALL "
                          "ON ALL TABLES IN SCHEMA public "
                          "TO {u};".format(u=user))
        pg_cursor.connection.commit()

    @staticmethod
    def perm_su(user, pg_cursor):
        """
        Defines, SQL statements for superuser permissions.
        """

        pg_cursor.execute("ALTER USER {u} WITH SUPERUSER;".format(u=user))
        pg_cursor.connection.commit()

    @staticmethod
    def create_user(user, pg_cursor):
        """
        Create role if doesn't exist.
        """

        pg_cursor.execute("DO $$ "
                          "BEGIN "
                          "CREATE ROLE {u} WITH LOGIN; "
                          "EXCEPTION WHEN duplicate_object THEN "
                          "RAISE NOTICE 'psqlusr: User already exists, skipping creation'; "
                          "END "
                          "$$;".format(u=user))
        pg_cursor.execute("GRANT psqlusr_managed TO {u}".format(u=user))
        pg_cursor.connection.commit()

    @staticmethod
    def purge_perms(user, pg_cursor, is_su=False):
        """
        Remove all permissions from role.
        """

        if is_su:
            pg_cursor.execute("ALTER USER {u} WITH NOSUPERUSER;".format(u=user))

        pg_cursor.execute("REVOKE USAGE, SELECT "
                          "ON ALL SEQUENCES IN SCHEMA public "
                          "FROM {u};".format(u=user))

        pg_cursor.execute("REVOKE CREATE ON SCHEMA public FROM {u};".format(u=user))

        pg_cursor.execute("REVOKE ALL PRIVILEGES "
                          "ON ALL TABLES IN SCHEMA public "
                          "FROM {u};".format(u=user))

        pg_cursor.connection.commit()

    def pg_connect(self, dbname):
        """
        Initiate connection to database.
        """
        return psycopg2.connect(dbname=dbname,
                                user=self.user,
                                password=self.password,
                                host=self.host)
