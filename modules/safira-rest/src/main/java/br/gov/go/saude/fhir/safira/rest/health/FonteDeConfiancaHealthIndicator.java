/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * Readiness da porta de confiança: DOWN enquanto não há acervo vigente (inclusive sem raiz que o
 * EU DSS consiga representar, quando lido pelos verificadores), UP com a geração e as
 * contagens (sem despejar certificados). Vive no {@code safira-rest} (registrado por
 * {@link SafiraHealthAutoConfiguration}) para que o {@code safira-steps} não dependa do Actuator.
 */
public class FonteDeConfiancaHealthIndicator implements HealthIndicator {

    private final FonteDeConfianca fonteDeConfianca;

    public FonteDeConfiancaHealthIndicator(FonteDeConfianca fonteDeConfianca) {
        this.fonteDeConfianca = fonteDeConfianca;
    }

    @Override
    public Health health() {
        return fonteDeConfianca.atual()
                .map(FonteDeConfiancaHealthIndicator::up)
                .orElseGet(() -> Health.down().withDetail("motivo", "acervo indisponível").build());
    }

    private static Health up(AcervoDeConfianca acervo) {
        return Health.up()
                .withDetail("geracao", acervo.geracao())
                .withDetail("raizes", acervo.raizes().size())
                .withDetail("intermediarias", acervo.intermediarias().size())
                .build();
    }
}
