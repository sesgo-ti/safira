/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;

/**
 * Converte o corpo JSON de {@code POST /validar} em {@link ValidationContext} sem perda.
 *
 * <p>Campos: {@code signature} (Signature FHIR completa), {@code bundle}, {@code provenance}
 * (Provenance final), {@code referenceTimestamp} e {@code policyIdentifierUri}. Entradas ausentes
 * seguem para o step {@code validation-context}, que devolve o código do IG; entradas de tipo
 * errado são rejeitadas aqui.
 */
public final class ValidationRequestParser {

    private ValidationRequestParser() {
    }

    public static ValidationContext parse(String body, SafiraOperationalConfigProperties operationalConfig) {
        JsonObject root = RequestFields.root(body);
        return ValidationContext.builder()
                .signatureJson(optionalObject(root, "signature", SignatureExceptionCode.FORMAT_SIGNATURE_MISSING))
                .bundleJson(optionalObject(root, "bundle", SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED))
                .provenanceJson(optionalObject(root, "provenance", SignatureExceptionCode.FORMAT_PROVENANCE_INVALID))
                .referenceTimestamp(RequestFields.timestamp(root, "referenceTimestamp"))
                .policyIdentifierUri(root.string("policyIdentifierUri").orElse(null))
                .operationalConfig(operationalConfig)
                .build();
    }

    private static JsonObject optionalObject(JsonObject root, String name, SignatureExceptionCode code) {
        if (root.get(name).isEmpty()) {
            return null;
        }
        return RequestFields.object(root, name, code);
    }
}
