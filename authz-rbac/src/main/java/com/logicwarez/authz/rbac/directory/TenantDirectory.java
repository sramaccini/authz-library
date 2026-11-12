package com.logicwarez.authz.rbac.directory;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.logicwarez.authz.rbac.RbacJdbc;

/**
 * Utenti di un tenant in sola lettura, per selettori, menzioni e notifiche: utenti attivi con almeno un ruolo sul
 * tenant, senza ruoli ne' altri tenant. Il tenant lo sceglie il chiamante (di solito quello della sessione, oppure
 * quello di un job senza sessione); l'endpoint {@code GET /api/v1/directory/users} usa sempre quello della sessione.
 */
public class TenantDirectory {

    /** Righe al massimo per ricerca. */
    public static final int MAX_LIMIT = 200;

    private static final String USERS = """
            SELECT u.username, u.email
              FROM app_user u
             WHERE u.is_active
               AND EXISTS (SELECT 1 FROM user_role ur WHERE ur.user_id = u.id AND ur.tenant_id = :tenant)
            """;

    private final RbacJdbc jdbc;

    public TenantDirectory(RbacJdbc jdbc) {
        this.jdbc = jdbc;
    }

    /** Utenti il cui username o email contiene il testo (tutti con un testo vuoto), per username, al massimo limit. */
    public List<DirectoryUser> search(String tenant, String text, int limit) {
        String needle = text == null ? "" : text.strip().toLowerCase(Locale.ROOT);
        String pattern = "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
        return jdbc.sql(USERS + """
                           AND (lower(u.username) LIKE :pattern ESCAPE '\\'
                                OR lower(coalesce(u.email, '')) LIKE :pattern ESCAPE '\\')
                         ORDER BY u.username
                         LIMIT :limit
                        """)
                .param("tenant", tenant)
                .param("pattern", pattern)
                .param("limit", Math.clamp(limit, 1, MAX_LIMIT))
                .query(DirectoryUser.class)
                .list();
    }

    /** L'utente, se attivo e con almeno un ruolo sul tenant. */
    public Optional<DirectoryUser> find(String tenant, String username) {
        return jdbc.sql(USERS + "   AND u.username = :username\n")
                .param("tenant", tenant)
                .param("username", username)
                .query(DirectoryUser.class)
                .optional();
    }

    public record DirectoryUser(String username, String email) {
    }
}
