package com.logicwarez.authz.rbac.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRawValue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;

/** Modelli JSON dell'API di amministrazione RBAC (/api/v1/admin). */
public final class AdminApi {

    static final String ROLE_CODE = "^[A-Z][A-Z0-9_]{1,99}$";
    static final String TENANT_CODE = "^[A-Za-z0-9_-]{1,50}$";
    static final String USERNAME = "^[A-Za-z0-9._@-]{1,150}$";
    static final String PERMISSION_CODE = "^[a-z0-9]+\\.[a-z0-9]+\\.[a-z0-9]+$";

    private AdminApi() {
    }

    public record PermissionView(String code, String description) {
    }

    public record RoleView(String code, String description, boolean system, int version,
                           SortedSet<String> permissions) {
    }

    public record RoleCreateRequest(
            @NotNull @Pattern(regexp = ROLE_CODE) String code,
            @Size(max = 255) String description,
            @NotNull @Size(max = 200) List<@Pattern(regexp = PERMISSION_CODE) String> permissions) {
    }

    /** Sostituisce descrizione e permessi; version e' quella letta (blocco ottimistico). */
    public record RoleUpdateRequest(
            @Size(max = 255) String description,
            @NotNull @Size(max = 200) List<@Pattern(regexp = PERMISSION_CODE) String> permissions,
            @NotNull @PositiveOrZero Integer version) {
    }

    public record TenantView(String code, String description) {
    }

    public record TenantCreateRequest(
            @NotNull @Pattern(regexp = TENANT_CODE) String code,
            @Size(max = 255) String description) {
    }

    /** Utente con le assegnazioni visibili all'amministratore (tenant -> ruoli). */
    public record UserView(String username, String email, boolean active,
                           Map<String, SortedSet<String>> assignments) {
    }

    public record TenantUserView(String username, String email, boolean active, SortedSet<String> roles) {
    }

    public record UserCreateRequest(
            @NotNull @Pattern(regexp = USERNAME) String username,
            @Email @Size(max = 255) String email) {
    }

    /** Solo amministratore globale: lo stato vale su tutti i tenant. Campi null = invariati. */
    public record UserUpdateRequest(Boolean active, @Email @Size(max = 255) String email) {
    }

    public record RoleAssignmentRequest(@NotNull @Size(max = 50) List<@Pattern(regexp = ROLE_CODE) String> roles) {
    }

    /** Richiesta di pseudonimizzazione: il nome che sostituisce quello dell'utente nel registro di audit. */
    public record ForgetRequest(@NotNull @Pattern(regexp = USERNAME) String pseudonym) {
    }

    /** Esito della pseudonimizzazione: voci di audit aggiornate e se la riga dell'utente e' stata eliminata. */
    public record ForgetResult(String pseudonym, String tenant, int auditEntries, boolean userDeleted) {
    }

    public record AuditEntry(long id,
                             @JsonProperty("occurred_at") OffsetDateTime occurredAt,
                             String actor,
                             @JsonProperty("actor_tenant") String actorTenant,
                             String action,
                             @JsonProperty("target_type") String targetType,
                             String target,
                             @JsonProperty("tenant_id") String tenantId,
                             @JsonProperty("before_state") @JsonRawValue String beforeState,
                             @JsonProperty("after_state") @JsonRawValue String afterState) {
    }
}
