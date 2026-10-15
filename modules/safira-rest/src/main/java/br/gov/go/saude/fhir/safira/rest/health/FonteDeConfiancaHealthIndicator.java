/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss.Uso;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Readiness da porta de confiança: DOWN enquanto não há acervo vigente (inclusive sem raiz que o
 * EU DSS consiga representar), UP com a geração e as contagens do que o DSS usa, mais os
 * certificados ignorados por ele (sem despejar certificados). Vive no {@code safira-rest}
 * (registrado por {@link SafiraHealthAutoConfiguration}) para que o {@code safira-steps} não
 * dependa do Actuator.
 */
public class FonteDeConfiancaHealthIndicator implements HealthIndicator {

    private final Supplier<Optional<Uso>> uso;

    public FonteDeConfiancaHealthIndicator(Supplier<Optional<Uso>> uso) {
        this.uso = uso;
    }

    @Override
    public Health health() {
        return uso.get()
                .map(FonteDeConfiancaHealthIndicator::up)
                .orElseGet(() -> Health.down().withDetail("motivo", "acervo indisponível").build());
    }

    private static Health up(Uso uso) {
        return Health.up()
                .withDetail("geracao", uso.geracao())
                .withDetail("raizes", uso.raizes())
                .withDetail("intermediarias", uso.intermediarias())
                .withDetail("ignorados", uso.ignorados())
                .build();
    }
}
