//! Decides whether a dbvalet.toml group role is safe to join, and whether the admin can use it.

use tokio_postgres::Client;

use super::CREATEROLE_SELF_GRANT_VERSION_NUM;

/// The first minor of each major whose `REASSIGN OWNED ... TO <group>` asks for SET on the group,
/// as `ALTER ... OWNER` does, instead of USAGE. 19 and later always ask for SET.
const REASSIGN_ASKS_SET_FROM: [(i32, i32); 3] = [(16, 160016), (17, 170012), (18, 180007)];

/// ADMIN counts only where `CREATE ROLE ... IN ROLE` can use it: held by the admin or by a role
/// whose privileges it has. A role reached only through `SET ROLE` can't be the grantor.
const ADMIN_GRANTS: &str = "
    SELECT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
           OR EXISTS (SELECT FROM pg_auth_members m
                      WHERE m.roleid = g.oid
                        AND m.admin_option
                        AND pg_has_role(current_user, m.member, 'USAGE')),
           pg_has_role(current_user, g.oid, 'USAGE'),
           {set}
    FROM pg_roles g
    WHERE g.rolname = $1";

/// What the admin holds on one group role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdminGrants {
    /// Needed to add each temporary login to the group.
    pub(super) admin: bool,
    usage: bool,
    /// `None` before PostgreSQL 16, which has no SET privilege.
    set: Option<bool>,
}

impl AdminGrants {
    /// What `REASSIGN OWNED ... TO <group>` needs on this server and the admin lacks. SET is asked
    /// for from 16 on, even on a minor that doesn't check it yet, so a minor update can't break
    /// teardown.
    pub(super) fn missing_for_reassign(&self, version_num: i32) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if asks_usage_for_reassign(version_num) && !self.usage {
            missing.push("USAGE");
        }
        if self.set == Some(false) {
            missing.push("SET");
        }
        missing
    }
}

fn asks_usage_for_reassign(version_num: i32) -> bool {
    match REASSIGN_ASKS_SET_FROM
        .iter()
        .find(|(major, _)| *major == version_num / 10000)
    {
        Some((_, first_set_minor)) => version_num < *first_set_minor,
        None => version_num < CREATEROLE_SELF_GRANT_VERSION_NUM,
    }
}

/// `None` when the group role doesn't exist.
pub(super) async fn read_admin_grants(
    client: &Client,
    member_of: &str,
    version_num: i32,
) -> Result<Option<AdminGrants>, tokio_postgres::Error> {
    let set = if version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        "pg_has_role(current_user, g.oid, 'SET')"
    } else {
        "NULL::bool"
    };
    let row = client
        .query_opt(&ADMIN_GRANTS.replace("{set}", set), &[&member_of])
        .await?;
    Ok(row.map(|row| AdminGrants {
        admin: row.get(0),
        usage: row.get(1),
        set: row.get(2),
    }))
}

/// Walks a group role and every ancestor it belongs to; `UNION` deduplicates diamond grants and
/// prevents cycles. Includes the starting role so a missing role returns zero rows.
const GROUP_ROLE_GRAPH: &str = "
    WITH RECURSIVE chain AS (
        SELECT oid, rolname, rolsuper, rolcreaterole, rolbypassrls, rolreplication
        FROM pg_roles
        WHERE rolname = $1
        UNION
        SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolbypassrls, r.rolreplication
        FROM chain c
        JOIN pg_auth_members m ON m.member = c.oid
        JOIN pg_roles r ON r.oid = m.roleid
    )
    SELECT rolname::text, rolsuper, rolcreaterole, rolbypassrls, rolreplication
    FROM chain
    WHERE rolname = $1
       OR rolsuper
       OR rolcreaterole
       OR rolbypassrls
       OR rolreplication
       OR starts_with(rolname::text, 'pg_')
    ORDER BY rolname::text ASC";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleEntry {
    name: String,
    superuser: bool,
    create_role: bool,
    bypass_rls: bool,
    replication: bool,
}

impl RoleEntry {
    fn dangerous_attributes(&self) -> Vec<&'static str> {
        let mut attributes = Vec::new();
        if self.superuser {
            attributes.push("SUPERUSER");
        }
        if self.create_role {
            attributes.push("CREATEROLE");
        }
        if self.bypass_rls {
            attributes.push("BYPASSRLS");
        }
        if self.replication {
            attributes.push("REPLICATION");
        }
        attributes
    }

    fn is_builtin_pg_role(&self) -> bool {
        self.name.starts_with("pg_")
    }

    fn is_dangerous(&self) -> bool {
        self.superuser
            || self.create_role
            || self.bypass_rls
            || self.replication
            || self.is_builtin_pg_role()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupRoleStatus {
    Safe,
    Missing,
    Dangerous(String),
}

pub(super) async fn inspect_group_role(
    client: &Client,
    member_of: &str,
) -> Result<GroupRoleStatus, tokio_postgres::Error> {
    let rows = client.query(GROUP_ROLE_GRAPH, &[&member_of]).await?;
    let entries: Vec<RoleEntry> = rows
        .into_iter()
        .map(|row| RoleEntry {
            name: row.get(0),
            superuser: row.get(1),
            create_role: row.get(2),
            bypass_rls: row.get(3),
            replication: row.get(4),
        })
        .collect();
    Ok(classify_group_role(member_of, &entries))
}

fn classify_group_role(member_of: &str, entries: &[RoleEntry]) -> GroupRoleStatus {
    if entries.is_empty() {
        return GroupRoleStatus::Missing;
    }
    let mut dangerous: Vec<&RoleEntry> = entries
        .iter()
        .filter(|entry| entry.is_dangerous())
        .collect();
    if dangerous.is_empty() {
        return GroupRoleStatus::Safe;
    }
    dangerous.sort_by(|a, b| {
        (b.name == member_of)
            .cmp(&(a.name == member_of))
            .then_with(|| a.name.cmp(&b.name))
    });
    let reasons: Vec<String> = dangerous
        .into_iter()
        .map(|entry| describe_role_danger(member_of, entry))
        .collect();
    GroupRoleStatus::Dangerous(reasons.join("; "))
}

fn describe_role_danger(member_of: &str, entry: &RoleEntry) -> String {
    let attributes = entry.dangerous_attributes();
    let builtin = entry.is_builtin_pg_role();
    if entry.name == member_of {
        return match (!attributes.is_empty(), builtin) {
            (true, false) => format!("has {}", attributes.join(", ")),
            (false, true) => "is a built-in pg_* role".to_owned(),
            (true, true) => {
                format!("is a built-in pg_* role and has {}", attributes.join(", "))
            }
            (false, false) => unreachable!("describe_role_danger only receives dangerous roles"),
        };
    }
    let mut traits = attributes;
    if builtin {
        traits.push("built-in pg_* role");
    }
    format!("is a member of `{}` ({})", entry.name, traits.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_entry(name: &str) -> RoleEntry {
        RoleEntry {
            name: name.to_owned(),
            superuser: false,
            create_role: false,
            bypass_rls: false,
            replication: false,
        }
    }

    fn grants(usage: bool, set: Option<bool>) -> AdminGrants {
        AdminGrants {
            admin: true,
            usage,
            set,
        }
    }

    #[test]
    fn reassign_on_postgresql_15_needs_usage_only() {
        assert_eq!(
            grants(false, None).missing_for_reassign(150020),
            vec!["USAGE"]
        );
        assert!(grants(true, None).missing_for_reassign(150020).is_empty());
    }

    #[test]
    fn reassign_on_minors_before_the_set_rule_needs_usage_and_set() {
        assert_eq!(
            grants(false, Some(false)).missing_for_reassign(160015),
            vec!["USAGE", "SET"]
        );
        assert_eq!(
            grants(false, Some(true)).missing_for_reassign(170011),
            vec!["USAGE"]
        );
        assert_eq!(
            grants(true, Some(false)).missing_for_reassign(180006),
            vec!["SET"]
        );
    }

    #[test]
    fn reassign_on_minors_with_the_set_rule_needs_set_only() {
        assert!(
            grants(false, Some(true))
                .missing_for_reassign(160016)
                .is_empty()
        );
        assert!(
            grants(false, Some(true))
                .missing_for_reassign(170012)
                .is_empty()
        );
        assert!(
            grants(false, Some(true))
                .missing_for_reassign(180007)
                .is_empty()
        );
        assert!(
            grants(false, Some(true))
                .missing_for_reassign(190000)
                .is_empty()
        );
        assert_eq!(
            grants(true, Some(false)).missing_for_reassign(190000),
            vec!["SET"]
        );
    }

    #[test]
    fn a_plain_group_role_and_non_pg_prefix_names_are_safe() {
        assert_eq!(
            classify_group_role("dbvalet_reader", &[role_entry("dbvalet_reader")]),
            GroupRoleStatus::Safe
        );
        assert_eq!(
            classify_group_role("pgx_reader", &[role_entry("pgx_reader")]),
            GroupRoleStatus::Safe
        );
        assert_eq!(
            classify_group_role("app_pg_reader", &[role_entry("app_pg_reader")]),
            GroupRoleStatus::Safe
        );
    }

    #[test]
    fn an_absent_group_role_is_classified_as_missing() {
        assert_eq!(
            classify_group_role("no_such_role", &[]),
            GroupRoleStatus::Missing
        );
    }

    #[test]
    fn a_group_role_with_any_dangerous_attribute_is_refused_naming_the_attribute() {
        let super_role = RoleEntry {
            superuser: true,
            ..role_entry("super_group")
        };
        assert_eq!(
            classify_group_role("super_group", &[super_role]),
            GroupRoleStatus::Dangerous("has SUPERUSER".to_owned())
        );

        let create_role = RoleEntry {
            create_role: true,
            ..role_entry("creator_group")
        };
        assert_eq!(
            classify_group_role("creator_group", &[create_role]),
            GroupRoleStatus::Dangerous("has CREATEROLE".to_owned())
        );

        let bypass_rls = RoleEntry {
            bypass_rls: true,
            ..role_entry("rls_group")
        };
        assert_eq!(
            classify_group_role("rls_group", &[bypass_rls]),
            GroupRoleStatus::Dangerous("has BYPASSRLS".to_owned())
        );

        let replication = RoleEntry {
            replication: true,
            ..role_entry("repl_group")
        };
        assert_eq!(
            classify_group_role("repl_group", &[replication]),
            GroupRoleStatus::Dangerous("has REPLICATION".to_owned())
        );
    }

    #[test]
    fn a_builtin_pg_role_is_refused() {
        assert_eq!(
            classify_group_role(
                "pg_execute_server_program",
                &[role_entry("pg_execute_server_program")],
            ),
            GroupRoleStatus::Dangerous("is a built-in pg_* role".to_owned())
        );
    }

    #[test]
    fn a_group_role_inheriting_from_dangerous_ancestors_names_each_offending_role() {
        let entries = vec![
            role_entry("pg_execute_server_program"),
            RoleEntry {
                create_role: true,
                ..role_entry("parent_admin")
            },
            RoleEntry {
                bypass_rls: true,
                ..role_entry("app_group")
            },
        ];
        assert_eq!(
            classify_group_role("app_group", &entries),
            GroupRoleStatus::Dangerous(
                "has BYPASSRLS; \
                 is a member of `parent_admin` (CREATEROLE); \
                 is a member of `pg_execute_server_program` (built-in pg_* role)"
                    .to_owned()
            )
        );
    }
}
