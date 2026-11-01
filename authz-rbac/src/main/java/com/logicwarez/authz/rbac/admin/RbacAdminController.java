package com.logicwarez.authz.rbac.admin;

import com.logicwarez.authz.rbac.admin.AdminApi.AuditEntry;
import com.logicwarez.authz.rbac.admin.AdminApi.PermissionView;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleAssignmentRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.RoleView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantUserView;
import com.logicwarez.authz.rbac.admin.AdminApi.TenantView;
import com.logicwarez.authz.rbac.admin.AdminApi.UserCreateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.UserUpdateRequest;
import com.logicwarez.authz.rbac.admin.AdminApi.UserView;
import com.logicwarez.authz.session.SessionContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * API di amministrazione RBAC per il frontend (/api/v1/admin/**), autenticata con la sessione di authz-bff.
 * Contratto in docs/authz-admin-openapi-spec.json, generato e verificato dal build (AdminOpenApiTest).
 */
@RestController
@RequestMapping("/api/v1/admin")
@Tag(name = "Amministrazione RBAC")
@Validated
public class RbacAdminController {

    private final RbacAdminService service;

    public RbacAdminController(RbacAdminService service) {
        this.service = service;
    }

    @GetMapping("/permissions")
    @Operation(summary = "Catalogo dei permessi (sola lettura)")
    public List<PermissionView> permissions() {
        return service.permissions();
    }

    @GetMapping("/roles")
    @Operation(summary = "Ruoli con i relativi permessi")
    public List<RoleView> roles() {
        return service.roles();
    }

    @PostMapping("/roles")
    @Operation(summary = "Crea un ruolo (solo amministratore globale)")
    @ResponseStatus(HttpStatus.CREATED)
    public RoleView createRole(@AuthenticationPrincipal SessionContext session,
                               @Valid @RequestBody RoleCreateRequest request) {
        return service.createRole(AdminScope.of(session), request);
    }

    @PutMapping("/roles/{code}")
    @Operation(summary = "Sostituisce descrizione e permessi di un ruolo non di sistema (solo globale, con version)")
    public RoleView updateRole(@AuthenticationPrincipal SessionContext session,
                               @PathVariable @Pattern(regexp = AdminApi.ROLE_CODE) String code,
                               @Valid @RequestBody RoleUpdateRequest request) {
        return service.updateRole(AdminScope.of(session), code, request);
    }

    @DeleteMapping("/roles/{code}")
    @Operation(summary = "Elimina un ruolo non assegnato e non di sistema (solo globale)")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteRole(@AuthenticationPrincipal SessionContext session,
                           @PathVariable @Pattern(regexp = AdminApi.ROLE_CODE) String code) {
        service.deleteRole(AdminScope.of(session), code);
    }

    @GetMapping("/tenants")
    @Operation(summary = "Tenant gestibili dall'amministratore")
    public List<TenantView> tenants(@AuthenticationPrincipal SessionContext session) {
        return service.tenants(AdminScope.of(session));
    }

    @PostMapping("/tenants")
    @Operation(summary = "Crea un tenant (solo amministratore globale)")
    @ResponseStatus(HttpStatus.CREATED)
    public TenantView createTenant(@AuthenticationPrincipal SessionContext session,
                                   @Valid @RequestBody TenantCreateRequest request) {
        return service.createTenant(AdminScope.of(session), request);
    }

    @GetMapping("/tenants/{tenant}/users")
    @Operation(summary = "Utenti con almeno un ruolo sul tenant, ordinati per username")
    public List<TenantUserView> tenantUsers(@AuthenticationPrincipal SessionContext session,
                                            @PathVariable @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                            @RequestParam(defaultValue = "50") int limit,
                                            @RequestParam(defaultValue = "0") int offset) {
        return service.tenantUsers(AdminScope.of(session), tenant, limit, offset);
    }

    @PutMapping("/tenants/{tenant}/users/{username}/roles")
    @Operation(summary = "Sostituisce i ruoli dell'utente sul tenant (lista vuota = nessun ruolo)")
    public UserView replaceUserRoles(@AuthenticationPrincipal SessionContext session,
                                     @PathVariable @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                     @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username,
                                     @Valid @RequestBody RoleAssignmentRequest request) {
        return service.replaceUserRoles(AdminScope.of(session), tenant, username, request);
    }

    @GetMapping("/users/{username}")
    @Operation(summary = "Utente con le assegnazioni visibili all'amministratore")
    public UserView user(@AuthenticationPrincipal SessionContext session,
                         @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username) {
        return service.user(AdminScope.of(session), username);
    }

    @PostMapping("/users")
    @Operation(summary = "Censisce un utente gia' presente nello IAM")
    @ResponseStatus(HttpStatus.CREATED)
    public UserView createUser(@AuthenticationPrincipal SessionContext session,
                               @Valid @RequestBody UserCreateRequest request) {
        return service.createUser(AdminScope.of(session), request);
    }

    @PatchMapping("/users/{username}")
    @Operation(summary = "Attiva/disattiva o cambia email (solo globale, non su se stessi)")
    public UserView updateUser(@AuthenticationPrincipal SessionContext session,
                               @PathVariable @Pattern(regexp = AdminApi.USERNAME) String username,
                               @Valid @RequestBody UserUpdateRequest request) {
        return service.updateUser(AdminScope.of(session), username, request);
    }

    @GetMapping("/audit")
    @Operation(summary = "Registro delle modifiche, piu' recenti prima (il delegato vede solo il proprio tenant)")
    public List<AuditEntry> audit(@AuthenticationPrincipal SessionContext session,
                                  @RequestParam(required = false) @Pattern(regexp = AdminApi.TENANT_CODE) String tenant,
                                  @RequestParam(defaultValue = "50") int limit,
                                  @RequestParam(defaultValue = "0") int offset) {
        return service.audit(AdminScope.of(session), tenant, limit, offset);
    }
}
