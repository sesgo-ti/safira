/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Validação de assinaturas JAdES conforme ETSI EN 319 102-1, via EU DSS.
 *
 * <p>Retorna os {@link Reports} do DSS (SimpleReport/DetailedReport/DiagnosticData), dos quais
 * se extraem {@code Indication} ({@code TOTAL_PASSED} | {@code TOTAL_FAILED} | {@code INDETERMINATE})
 * e {@code SubIndication} — o modelo triádico que fundamenta o tratamento de garantia
 * indeterminada no pipeline de validação.
 */
public class JadesValidationService {

    /**
     * Valida o documento JWS com o verificador fornecido, no nível {@code ARCHIVAL_DATA}
     * (processa sigTst, material LT embutido e arcTst quando presentes).
     *
     * @param jwsJson  JWS em General JSON Serialization
     * @param verifier verificador com âncoras de confiança e fontes de revogação
     */
    public Reports validate(String jwsJson, CertificateVerifier verifier) {
        return validate(jwsJson, verifier, ValidationLevel.ARCHIVAL_DATA);
    }

    public Reports validate(String jwsJson, CertificateVerifier verifier, ValidationLevel level) {
        Objects.requireNonNull(jwsJson, "jwsJson não pode ser nulo");
        Objects.requireNonNull(verifier, "verifier não pode ser nulo");

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
                new InMemoryDocument(jwsJson.getBytes(StandardCharsets.UTF_8)));
        validator.setCertificateVerifier(verifier);
        validator.setValidationLevel(level);
        return validator.validateDocument();
    }
}
