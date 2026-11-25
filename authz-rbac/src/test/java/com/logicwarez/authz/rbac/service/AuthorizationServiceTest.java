package com.logicwarez.authz.rbac.service;

import com.logicwarez.authz.session.UserNotAuthorizedException;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository.ActiveUser;
import com.logicwarez.authz.rbac.repository.AuthorizationRepository.GrantRow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

class AuthorizationServiceTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private AuthorizationRepository repository;
    private AuthorizationService service;

    @BeforeEach
    void setUp() {
        repository = mock(AuthorizationRepository.class);
        service = new AuthorizationService(repository);
        user(null);
    }

    private void user(String lastTenant) {
        when(repository.findActiveUser("mario.rossi"))
                .thenReturn(Optional.of(new ActiveUser(USER_ID, "mario.rossi", "mario.rossi@example.org", lastTenant)));
    }

    @Test
    void singleTenantIsSelectedAutomatically() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", "Tenant A", "DOCTOR", "clinical.patient.read"),
                new GrantRow("TENANT_A", "Tenant A", "DOCTOR", "clinical.patient.write"),
                new GrantRow("TENANT_A", "Tenant A", "CUP_OPERATOR", "clinical.patient.read")));

        AuthorizationContext ctx = service.resolve("mario.rossi", null);

        assertThat(ctx.tenantId()).isEqualTo("TENANT_A");
        assertThat(ctx.roles()).containsExactly("CUP_OPERATOR", "DOCTOR");
        assertThat(ctx.permissions()).containsExactly("clinical.patient.read", "clinical.patient.write");
        verify(repository).updateLastTenant(USER_ID, "TENANT_A");
    }

    @Test
    void rolesAreScopedToTheRequestedTenant() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", null, "DOCTOR", "clinical.patient.write"),
                new GrantRow("TENANT_B", "Sede di Roma", "CUP_OPERATOR", "booking.appointment.manage")));

        AuthorizationContext ctx = service.resolve("mario.rossi", "TENANT_B");

        assertThat(ctx.roles()).containsExactly("CUP_OPERATOR");
        assertThat(ctx.permissions()).containsExactly("booking.appointment.manage");
        // etichetta mancante: si mostra il codice
        assertThat(ctx.availableTenants()).containsExactly(Map.entry("TENANT_A", "TENANT_A"),
                Map.entry("TENANT_B", "Sede di Roma"));
        verify(repository).updateLastTenant(USER_ID, "TENANT_B");
    }

    @Test
    void multipleTenantsWithoutSelectionUseTheLastOne() {
        user("TENANT_B");
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", null, "DOCTOR", null),
                new GrantRow("TENANT_B", null, "VIEWER", null)));

        AuthorizationContext ctx = service.resolve("mario.rossi", null);

        assertThat(ctx.tenantId()).isEqualTo("TENANT_B");
        assertThat(ctx.roles()).containsExactly("VIEWER");
    }

    @Test
    void multipleTenantsWithoutHistoryUseTheFirstOne() {
        user("TENANT_GONE"); // ultimo tenant su cui l'utente non ha piu' ruoli
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_B", null, "DOCTOR", null),
                new GrantRow("TENANT_A", null, "DOCTOR", null)));

        assertThat(service.resolve("mario.rossi", null).tenantId()).isEqualTo("TENANT_A");
    }

    @Test
    void tenantWithoutRolesIsRejected() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(new GrantRow("TENANT_A", null, "DOCTOR", null)));

        assertThatThrownBy(() -> service.resolve("mario.rossi", "TENANT_X"))
                .isInstanceOf(UserNotAuthorizedException.class);
        verify(repository, never()).updateLastTenant(any(), any());
    }

    @Test
    void unknownOrInactiveUserIsRejected() {
        when(repository.findActiveUser("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.resolve("ghost", null))
                .isInstanceOf(UserNotAuthorizedException.class);
    }

    // --- Ruoli operativi (ADR-28 di Quadrava) ---

    /** Un ruolo di base e due operativi, la separazione dei compiti: chi inserisce un ordine non lo approva. */
    private void operationalGrants() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", null, "USER", "profile.profile.read", "Utente", true),
                new GrantRow("TENANT_A", null, "CLERK", "orders.order.create", "Addetto", false),
                new GrantRow("TENANT_A", null, "APPROVER", "orders.order.approve", null, false),
                new GrantRow("TENANT_B", null, "AUDITOR", "audit.log.read", "Revisore", false)));
    }

    private void user(String lastTenant, String lastRole) {
        when(repository.findActiveUser("mario.rossi")).thenReturn(Optional.of(
                new ActiveUser(USER_ID, "mario.rossi", "mario.rossi@example.org", lastTenant, lastRole)));
    }

    @Test
    void operationalRolesOneAtATimeWithTheBaseRoles() {
        operationalGrants();

        AuthorizationContext ctx = service.resolve("mario.rossi", "TENANT_A", "CLERK");

        assertThat(ctx.currentRole()).isEqualTo("CLERK");
        // senza descrizione si mostra il codice; i ruoli di base non si scelgono
        assertThat(ctx.operationalRoles()).containsExactly(Map.entry("APPROVER", "APPROVER"),
                Map.entry("CLERK", "Addetto"));
        assertThat(ctx.roles()).containsExactly("APPROVER", "CLERK", "USER");
        assertThat(ctx.permissions()).containsExactly("orders.order.create", "profile.profile.read");
        verify(repository).updateLastRole(USER_ID, "CLERK");
    }

    @Test
    void withoutAChoiceTheLastRoleThenTheFirst() {
        user("TENANT_A", "CLERK");
        operationalGrants();
        assertThat(service.resolve("mario.rossi", null).currentRole()).as("ultimo usato").isEqualTo("CLERK");

        user("TENANT_A", "AUDITOR"); // ultimo ruolo, ma di un altro tenant
        assertThat(service.resolve("mario.rossi", null).currentRole()).as("primo per codice").isEqualTo("APPROVER");
        // un ruolo che l'utente non ha sul tenant non si attiva: vale l'ultimo o il primo
        assertThat(service.resolve("mario.rossi", "TENANT_A", "ADMIN").permissions())
                .containsExactly("orders.order.approve", "profile.profile.read");
    }

    @Test
    void withoutOperationalRolesAllTheRolesAsBefore() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(
                new GrantRow("TENANT_A", null, "DOCTOR", "clinical.patient.write"),
                new GrantRow("TENANT_A", null, "CUP_OPERATOR", "booking.appointment.manage")));

        AuthorizationContext ctx = service.resolve("mario.rossi", null, "DOCTOR");

        assertThat(ctx.currentRole()).isNull();
        assertThat(ctx.operationalRoles()).isEmpty();
        assertThat(ctx.permissions()).containsExactly("booking.appointment.manage", "clinical.patient.write");
        verify(repository, never()).updateLastRole(any(), any());
    }

    @Test
    void aTokenHasAllTheRolesAndChangesNoLastRole() {
        user("TENANT_A", "CLERK");
        operationalGrants();

        AuthorizationContext ctx = service.resolve("mario.rossi", "TENANT_A", false);

        assertThat(ctx.currentRole()).isNull();
        assertThat(ctx.operationalRoles()).isEmpty();
        assertThat(ctx.permissions()).containsExactly("orders.order.approve", "orders.order.create",
                "profile.profile.read");
        verify(repository, never()).updateLastRole(any(), any());
    }

    @Test
    void roleWithoutPermissionsIsKept() {
        when(repository.findGrants(USER_ID)).thenReturn(List.of(new GrantRow("TENANT_A", null, "VIEWER", null)));

        AuthorizationContext ctx = service.resolve("mario.rossi", null);

        assertThat(ctx.roles()).containsExactly("VIEWER");
        assertThat(ctx.permissions()).isEmpty();
    }
}
