/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import org.erdtman.jcs.JsonCanonicalizer;

import java.util.ArrayList;
import java.util.List;

@StepId("json-canonicalizer")
public class JsonCanonicalizationStep implements SigningStep {

    public static final String CANONICALIZED_RESOURCES_KEY = "canonicalizedResources";

    @SuppressWarnings("unchecked")
    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        List<String> preparedResources = context
                .getAttribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, List.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                        "Os recursos preparados não foram encontrados no contexto. Verifique se o step payload-preparation foi executado."));

        try {
            List<String> canonicalized = new ArrayList<>();
            for (String resourceJson : preparedResources) {
                JsonCanonicalizer canonicalizer = new JsonCanonicalizer(resourceJson);
                canonicalized.add(canonicalizer.getEncodedString());
            }

            SigningContext updated = context.toBuilder()
                    .attribute(CANONICALIZED_RESOURCES_KEY, List.copyOf(canonicalized))
                    .build();

            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                    "Erro na canonicalização do JSON: " + e.getMessage(), e);
        }
    }
}
