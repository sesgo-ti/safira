/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.certificate.PkixResults;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Passo {@code current-chain}: para JAdES-B-B (C22; validar 4.2/6.2), a cadeia ICP-Brasil do
 * titular deve estar válida e conclusivamente não revogada no instante atual — validação PKIX
 * completa (RFC 5280) e revogação de todo o caminho pela lib icpbrasil-truststore. Em JAdES-B-T
 * a validade é avaliada no intervalo comprovado pelo carimbo ({@code dss-validation}).
 */
@StepId("current-chain")
public class CurrentChainStep implements ValidationStep {

    private final PkixCertificateValidator validator;

    public CurrentChainStep(PkixCertificateValidator validator) {
        this.validator = validator;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        if (context.getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class).orElse(JadesLevel.B_B) != JadesLevel.B_B) {
            return StepResult.success(getName(), context);
        }
        List<X509Certificate> chain = context.getCertificateChain().orElse(List.of());
        ValidationResult result = validator.validate(chain.getFirst(), chain.subList(1, chain.size()));
        return PkixResults.violation(result)
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }
}
