/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.certificate.PkixResults;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Passo {@code pkix-chain-validation}: etapa 2 do caso de uso de criação.
 *
 * <p>Decodifica a entrada 4 (certificado do signatário, opcionalmente com a cadeia) e delega ao
 * {@link PkixCertificateValidator} da lib icpbrasil-truststore a construção e validação completa
 * do caminho (RFC 5280, pelo PKIX do JDK), ancorada nas raízes do acervo ICP-Brasil, com a
 * revogação de cada certificado não raiz verificada via OCSP/CRL. Os certificados recebidos são
 * apenas candidatos: a confiança vem exclusivamente do acervo.
 *
 * <p>Escreve {@code certificateChain} = caminho validado + âncora (folha primeiro) e o atributo
 * {@link #REVOCATION_EVIDENCE_KEY} com as evidências de revogação aceitas.
 */
@StepId("pkix-chain-validation")
public class PkixChainValidationStep implements SigningStep {

    public static final String REVOCATION_EVIDENCE_KEY = "revocationEvidence";

    private final PkixCertificateValidator validator;

    public PkixChainValidationStep(PkixCertificateValidator validator) {
        this.validator = validator;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        List<String> raw = context.getRawCertificateChain();
        if (raw == null || raw.isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "Nenhum certificado do signatário foi informado.", context);
        }
        List<X509Certificate> certificates = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            byte[] der;
            try {
                der = Base64.getDecoder().decode(raw.get(i));
            } catch (IllegalArgumentException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                        "O certificado na posição " + i + " não está em Base64 padrão.", context);
            }
            try {
                certificates.add((X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der)));
            } catch (CertificateException | ClassCastException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "O certificado na posição " + i + " não é um X.509 DER válido.", context);
            }
        }

        ValidationResult result = validator.validate(certificates.getFirst(), certificates.subList(1, certificates.size()));
        if (!(result instanceof ValidationResult.Valid valid)) {
            return PkixResults.violation(result)
                    .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                    .orElseThrow();
        }
        List<X509Certificate> chain = new ArrayList<>(valid.path());
        chain.add(valid.anchor());
        if (chain.size() < 2) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "A cadeia deve conter ao menos o certificado do signatário e a raiz ICP-Brasil.", context);
        }
        return StepResult.success(getName(), context.toBuilder()
                .certificateChain(chain.toArray(X509Certificate[]::new))
                .attribute(REVOCATION_EVIDENCE_KEY, valid.evidence())
                .build());
    }
}
