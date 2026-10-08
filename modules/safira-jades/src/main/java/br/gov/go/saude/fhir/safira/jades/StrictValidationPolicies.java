/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Políticas de validação padrão do EU DSS endurecidas para o Safira.
 *
 * <p>Única alteração: {@code SupportedCriticalExtensions} do certificado do signatário passa de
 * {@code WARN} para {@code FAIL} — extensão crítica não reconhecida no certificado folha recusa a
 * validação (RFC 5280 §4.2). A lista de extensões suportadas permanece a do DSS.
 */
final class StrictValidationPolicies {

    /** Política padrão do {@code CertificateValidator} (validação avulsa de certificado). */
    static final DSSDocument CERTIFICATE = harden("/policy/certificate-constraint.xml");
    /** Política padrão do {@code SignedDocumentValidator} (validação de assinatura). */
    static final DSSDocument SIGNATURE = harden("/policy/constraint.xml");

    private StrictValidationPolicies() {
    }

    private static DSSDocument harden(String resource) {
        ValidationPolicyFacade facade = ValidationPolicyFacade.newFacade();
        try (InputStream in = StrictValidationPolicies.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Política padrão do EU DSS não encontrada: " + resource);
            }
            ConstraintsParameters policy = facade.unmarshall(in);
            policy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate()
                    .getSupportedCriticalExtensions().setLevel(Level.FAIL);
            return new InMemoryDocument(facade.marshall(policy).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Não foi possível preparar a política de validação " + resource, e);
        }
    }
}
