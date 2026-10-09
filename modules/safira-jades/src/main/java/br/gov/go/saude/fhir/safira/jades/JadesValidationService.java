/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
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
 *
 * <p>Usa a política padrão do DSS com extensão crítica desconhecida no certificado do signatário
 * como {@code FAIL} (RFC 5280 §4.2).
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
        validator.setSignaturePolicyProvider(offlineSignaturePolicyProvider());
        return validator.validateDocument(StrictValidationPolicies.SIGNATURE);
    }

    /**
     * Provedor de política de assinatura sem rede: a URI do {@code sigPId}/{@code spURI} vem da
     * assinatura (não confiável) e nunca deve ser baixada. O DSS 6.5 hoje não baixa por padrão, mas
     * o getter padrão instala {@code NativeHTTPDataLoader} ilimitado; fixamos o comportamento aqui.
     */
    private static SignaturePolicyProvider offlineSignaturePolicyProvider() {
        SignaturePolicyProvider provider = new SignaturePolicyProvider();
        provider.setDataLoader(new IgnoreDataLoader());
        return provider;
    }
}
