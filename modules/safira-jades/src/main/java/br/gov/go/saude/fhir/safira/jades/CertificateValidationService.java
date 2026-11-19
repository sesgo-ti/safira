/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Validação de um certificado avulso pelo EU DSS ({@link CertificateValidator}, política
 * {@link StrictValidationPolicies}, instante atual): cadeia, validade, revogação e restrições do
 * certificado do signatário conforme o verificador e a política recebidos.
 */
public class CertificateValidationService {

    private final StrictValidationPolicies policy;

    /** Com a política versionada sem restrição de política de certificado. */
    public CertificateValidationService() {
        this(StrictValidationPolicies.padrao());
    }

    public CertificateValidationService(StrictValidationPolicies policy) {
        this.policy = Objects.requireNonNull(policy, "policy não pode ser nulo");
    }

    /**
     * @param certificate certificado a validar
     * @param candidates  certificados recebidos junto (candidatos à cadeia, nunca confiáveis por si)
     * @param verifier    verificador novo, desta chamada — recebe os candidatos como adjuntos
     * @return relatórios com o binário dos certificados no diagnóstico (para recompor a cadeia)
     */
    public CertificateReports validate(X509Certificate certificate, List<X509Certificate> candidates,
                                       CommonCertificateVerifier verifier) {
        Objects.requireNonNull(certificate, "certificate não pode ser nulo");
        Objects.requireNonNull(verifier, "verifier não pode ser nulo");
        if (!candidates.isEmpty()) {
            CommonCertificateSource supplied = new CommonCertificateSource();
            candidates.forEach(candidate -> CertificateVerifierFactory.token(candidate).ifPresent(supplied::addCertificate));
            verifier.addAdjunctCertSources(supplied);
        }
        CertificateValidator validator = CertificateValidator.fromCertificate(new CertificateToken(certificate));
        validator.setCertificateVerifier(verifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
        return validator.validate(policy.document());
    }
}
