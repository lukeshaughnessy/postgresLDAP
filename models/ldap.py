"""
psqlusr LDAP module.
"""
import re
import logging
# pylint: disable-msg=E0611
from ldap import modlist, ldapobject, LDAPError, SCOPE_BASE, ALREADY_EXISTS

LDAP_HOST_BASE = "cn=computers,cn=accounts,dc=internal,dc=n0q,dc=eu"
LDAP_USER_BASE = "cn=users,cn=accounts,dc=internal,dc=n0q,dc=eu"
LDAP_GROUP_BASE = "cn=groups,cn=accounts,dc=internal,dc=n0q,dc=eu"
LDAP_HBACSERVICE_BASE = "cn=hbacservices,cn=hbac,dc=internal,dc=n0q,dc=eu"

LDAP_USER_OBJECTCLASS = "ipasshuser"
LDAP_HBACRULE_OBJECTCLASS = "ipahbacrule"
LDAP_USERGROUP_OBJECTCLASS = "ipausergroup"
LDAP_HOST_OBJECTCLASS = "ipasshhost"


class PsqlLdap:
    """
    Handles connection to the LDAP server
    """

    def __init__(self, args, perms):

        self.ldapusername = args.ldapuser
        self.ldappassword = args.ldappassword
        self.hostname = args.hostname
        self.postgresql_service = args.psqlservice
        self.postgres_admin_db = args.pgadmindb
        self.perm_ranking = perms
        self.ldap_obj = ldapobject.LDAPObject("ldap://{H}:{P}".format(H=args.ldaphost,
                                                                      P=args.ldapport))
        try:
            self.ldap_obj.simple_bind_s("cn=%s" % self.ldapusername,
                                        self.ldappassword)

        except LDAPError as err:
            logging.error(err)
            logging.error("Fetching from LDAP unsuccessful")
            raise SystemError

    def psqlusr_ldap_init(self, default_rules):
        """
        Creates a new hbac rule and service during initialisation.
        """
        try:
            self.ldap_obj.add_s("cn=%s,cn=hbacservices,cn=hbac,dc=internal,dc=n0q,dc=eu"
                                % self.postgresql_service,
                                modlist.addModlist(
                                    {'objectClass': [b'ipaobject', b'ipahbacservice'],
                                     'description': [b'psqlusr service for postgresql']}))
        except ALREADY_EXISTS:
            logging.info("HBAC service already exists, skipping creation")
        except LDAPError as err:
            logging.error(err)
            raise SystemError

        try:
            hbacrule_name = "psqlusr_" + self.hostname
            member_user = []
            for line in default_rules:
                line_split = line.split(":")
                if len(line_split) != 4:
                    continue
                if line_split[1] == "group":
                    member_user.append(b"%b" % str("cn={},".format(line_split[0])
                                                   + LDAP_GROUP_BASE).encode())
                elif line_split[1] == "user":
                    member_user.append(b"%b" % str("uid={},".format(line_split[0])
                                                   + LDAP_USER_BASE).encode())
                else:
                    continue
            hbacrule_modlist = modlist.addModlist({
                'objectClass': [b'ipaassociation', b'ipahbacrule'],
                'cn': [b"%b" % str(hbacrule_name).encode()],
                'accessRuleType': [b'allow'],
                'ipaEnabledFlag': [b'TRUE'],
                'memberService': [b'cn=%b,cn=hbacservices,cn=hbac,dc=internal,dc=n0q,dc=eu'
                                  % str(self.postgresql_service).encode()],
                'memberHost': [b'fqdn=%b,%b' % (str(self.hostname).encode(),
                                                LDAP_HOST_BASE.encode())],
                'description': [b'gitlab.n0q.eu/platform/wiki/wikis/psqlusr/deployment-usage\n'
                                b'Place your permissions after this line; each on a new line!\n\n' +
                                b"%b" % "\n".join(default_rules).encode()
                                ],
                'memberUser': member_user
            })

            self.ldap_obj.add_s("ipaUniqueID=%s,cn=hbac,dc=internal,dc=n0q,dc=eu" % hbacrule_name,
                                hbacrule_modlist)

        except ALREADY_EXISTS:
            logging.info("HBAC rule already exists, skipping creation")
        except LDAPError as err:
            logging.error(err)
            raise SystemError

    def psqlusr_ldap_main(self):
        """
        Calls the normalise_role_maps method to return role maps.
        """
        return self.norlmalise_role_maps(self.role_search())

    def role_search(self):
        """
        Calls the self.hbac_search() method to determine the hbacrule(s)
        the host is a member of; either directly or through a hostgroup.
        Subsequently invokes the self.hbac_rule_description method
        to determine the entries in the hbacrule(s) description that are valid,
        and mapped to entries in the "Who" section ie users/usergroups.

        Returns the users and their respective database(s) to permission map
        as defined in the hbac_rule's description.
        For both the groups and users in the "Who" section of the hbac_rule.

        :return:
        {'groups': [('psqlusruser','psqlusrdb:RO')], 'users': [('psqlusrtest','psqlusrdb:RW')]}

        """

        hbac_rule = self.hbac_search(self.hostname)

        hbac_rule_descriptions = self.hbac_descriptions(hbac_rule) if hbac_rule else []

        role_permission_map = {"groups": [], "users": []}

        for line in hbac_rule_descriptions:
            try:
                search_res = self.ldap_obj.search_s(line.split(":")[0],
                                                    SCOPE_BASE, "objectclass=*")
            except LDAPError as err:
                logging.error(err)
                logging.error("Fetching from LDAP unsuccessful")
                raise SystemError

            if search_res:
                # For a search, if the key doesn't exist eg member, memberService,
                # LDAP omits it from the response dict as opposed to returning an empty list.
                # Hence you need to check if the key exists eg item[1].get("member")

                for item in search_res:
                    ldap_usergroup_objectclass = LDAP_USERGROUP_OBJECTCLASS.encode("utf-8")
                    if ldap_usergroup_objectclass in item[1].get("objectClass") \
                            and item[1].get("member"):
                        for user in item[1].get("member"):
                            role_permission_map.get("groups").append((
                                re.search('(?<=uid=).*(?=,' + LDAP_USER_BASE + ')',
                                          user.decode("utf-8")).group(0),
                                line.split(":", 1)[-1]))

                    if LDAP_USER_OBJECTCLASS.encode("utf-8") in item[1].get("objectClass"):
                        role_permission_map.get("users").append(
                            (re.search('(?<=uid=).*(?=,' + LDAP_USER_BASE + ')',
                                       item[0]).group(0), line.split(":", 1)[-1]))
        return role_permission_map

    def hbac_search(self, hostname):
        """
        Queries LDAP for the host and any collections it's a member of
        eg hostgroups, hbacrules etc.
        Filters out and returns which collections have an hbacrule and if so,
        whether it has the required service attached to it.

        :return:
        [{'description':
            [psqlusrtest:users:psqlusrdb:RW'],
        'memberService':
            [b'cn=postgresql,cn=hbacservices,cn=hbac,dc=internal,dc=n0q,dc=eu'],
        'memberHost':
            [b'cn=duarte-test-host-group,cn=hostgroups,cn=accounts,dc=internal,dc=n0q,dc=eu'],
        'memberUser':
            [b'uid=psqlusrtest,cn=users,cn=accounts,dc=internal,dc=n0q,dc=eu'],
        'objectClass':
            [b'ipaassociation', b'ipahbacrule'], 'accessRuleType': [b'allow'],
        'ipaEnabledFlag': [b'TRUE'],
        'cn': [b'test-duarte-hbac'],
        'ipaUniqueID': [b'742f2384-12bb-11ea-91ba-024724cd6604']}]

        """

        try:
            search_res = self.ldap_obj.search_s("fqdn={h},{b}".format(h=hostname, b=LDAP_HOST_BASE),
                                                SCOPE_BASE,
                                                "objectclass={o}".format(o=LDAP_HOST_OBJECTCLASS))
        except LDAPError as err:
            logging.error(err)
            logging.error(msg="Check hostname: %s" % self.hostname)
            logging.error("Fetching from LDAP unsuccessful")
            raise SystemError

        member_of = []
        for _, attrs in search_res:
            if attrs.get("memberOf"):
                member_of.extend(attrs.get("memberOf"))

        hbac_rules = []
        for item in member_of:
            try:
                search_res = self.ldap_obj.search_s(item.decode("utf-8"),
                                                    SCOPE_BASE,
                                                    "objectclass=%s" % LDAP_HBACRULE_OBJECTCLASS)
            except LDAPError as err:
                logging.error(err)
                logging.error("Fetching from LDAP unsuccessful")
                raise SystemError

            for _, attrs in search_res:

                if attrs.get("memberService") and \
                        "cn={s},{b}".format(s=self.postgresql_service,
                                            b=LDAP_HBACSERVICE_BASE) in \
                        [x.decode("utf-8") for x in attrs.get("memberService")]:
                    hbac_rules.append(attrs)

        return hbac_rules

    @staticmethod
    def hbac_descriptions(hbac_rules):
        """
        Parses the description in an hbacrule and determines entries
        that also exist in the hbacrule's "Who" section.
        Returns all the descriptions for every hbacrule as one list.

        :return:
        [cn=psqlanalysts,cn=groups,cn=accounts,dc=internal,dc=n0q,dc=eu:psqlusrdb:RO
        uid=psqlusrtest,cn=users,cn=accounts,dc=internal,dc=n0q,dc=eu:psqlusrdb:RW']
        """

        valid_hbac_rule_descriptions = []

        for rule in hbac_rules:
            if rule.get("description"):

                # Search for an hbacrule returns the description as a single string in a list.
                # For every entry in the hbacrule's  description, match it to
                # an entry in the hbacrule's who/users/usersgroups.
                # Ignore lines that don't have entries in the Who section.
                for line in rule.get("description")[0].decode("utf-8").split("\n"):
                    line_split = line.split(":")
                    if len(line_split) != 4:
                        continue
                    if line_split[1] == "group":
                        account_dit = "cn={},".format(line_split[0]) + LDAP_GROUP_BASE
                    elif line_split[1] == "user":
                        account_dit = "uid={},".format(line_split[0]) + LDAP_USER_BASE
                    else:
                        continue

                    if rule.get("memberUser") \
                            and account_dit.encode("utf-8") in rule.get("memberUser"):
                        valid_hbac_rule_descriptions.append(
                            account_dit + ":" + ":".join(line_split[2:]))
        return valid_hbac_rule_descriptions

    def norlmalise_role_maps(self, role_maps):
        """
        Takes the role_maps as input;
        Returns a dict of the effective database-permission maps for each user.
        Criterion:
        1) Each user has ONLY one permission assigned per database.
        2) Permissions are ranked in increasing weight:
            RO(read-only access), RW(read-write access), SU (superuser).
        3) For a user:
            appearing in multiple groups, for the same database,
            the effective permission is LEAST PRIVILEGE.
        4) For a user:
            in both a group and as a directly added user, for the same database,
            the effective permission is WHATEVER THE DIRECTLY-ADDED USER HAS.

        Returns the role_maps normalised by db:
        normalised_role_maps_by_usr = {'psqlusruser_1': {'psqlusrdb_1': 'RW'},
                                       'psqlusruser_2': {'psqlusrdb_1': 'RO', 'psqlusrdb_2': 'RO'}}

        normalised_role_maps_by_db = {'psqlusrdb_1': {'psqlusruser_1': 'RW', 'psqlusruser_2': 'RO'},
                                      'psqlusrdb_2': {'psqlusruser_2': 'RO'}}

        """

        normalised_role_maps_by_usr = {}

        for role_pair in role_maps.get("groups"):
            usr = role_pair[0]
            permission = role_pair[1].split(":")[-1]
            role_pair_perm_rank = self.perm_ranking.get(permission)

            if role_pair_perm_rank:

                databases = role_pair[1].split(":")[0]

                if permission == "SU" and databases == "*":
                    user_role_map = {self.postgres_admin_db: "SU"}

                elif permission != "SU":
                    user_role_map = {database.strip(): permission
                                     for database in databases.split(",")}
                else:
                    continue

                if usr in normalised_role_maps_by_usr:
                    # Python syntax for comparing keys of dictionaries (sets)
                    duplicate_databases = normalised_role_maps_by_usr.get(usr).keys() & \
                                          user_role_map.keys()
                    for dbname in duplicate_databases:
                        if self.perm_ranking.get(normalised_role_maps_by_usr.get(usr).get(dbname)) \
                                < self.perm_ranking.get(user_role_map.get(dbname)):
                            del user_role_map[dbname]
                    normalised_role_maps_by_usr[usr].update(user_role_map)
                    if len(normalised_role_maps_by_usr[usr]) > 1 and \
                            normalised_role_maps_by_usr[usr].get(self.postgres_admin_db) == "SU":
                        del normalised_role_maps_by_usr[usr][self.postgres_admin_db]
                    continue

                normalised_role_maps_by_usr[usr] = user_role_map

        for role_pair in role_maps.get("users"):
            usr = role_pair[0]
            permission = role_pair[1].split(":")[-1]
            databases = role_pair[1].split(":")[0]

            if self.perm_ranking.get(permission):
                if permission == "SU" and databases == "*":
                    user_role_map = {self.postgres_admin_db: "SU"}

                elif permission != "SU":
                    user_role_map = {database.strip(): permission
                                     for database in databases.split(",")}
                else:
                    continue
                normalised_role_maps_by_usr[usr] = user_role_map

        normalised_role_maps_by_db = {"*": {}}
        for usr, db_perm in normalised_role_maps_by_usr.items():
            for database, perm in db_perm.items():
                try:
                    normalised_role_maps_by_db[database][usr] = perm
                except KeyError:
                    normalised_role_maps_by_db[database] = {}
                    normalised_role_maps_by_db[database][usr] = perm
        return normalised_role_maps_by_db
