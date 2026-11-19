/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;

import java.util.Objects;

/**
 * Validação de um {@code TimeStampToken} RFC 3161 avulso pelo EU DSS
 * ({@link DetachedTimestampValidator}): message imprint sobre os dados carimbados, assinatura
 * CMS, certificado da TSA, cadeia e revogação conforme o verificador recebido.
 */
public class TimestampValidationService {

    /**
     * @param timestampToken  {@code TimeStampToken} (CMS ContentInfo DER)
     * @param timestampedData dados cujo hash é o message imprint
     * @param verifier        verificador com as âncoras da TSA
     */
    public Reports validate(byte[] timestampToken, byte[] timestampedData, CertificateVerifier verifier) {
        Objects.requireNonNull(timestampToken, "timestampToken não pode ser nulo");
        Objects.requireNonNull(timestampedData, "timestampedData não pode ser nulo");
        Objects.requireNonNull(verifier, "verifier não pode ser nulo");
        DetachedTimestampValidator validator = new DetachedTimestampValidator(new InMemoryDocument(timestampToken));
        validator.setTimestampedData(new InMemoryDocument(timestampedData));
        validator.setCertificateVerifier(verifier);
        return validator.validateDocument();
    }
}
