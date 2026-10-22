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
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import br.gov.go.saude.fhir.safira.steps.certificate.ProfileResult;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;

import java.security.cert.X509Certificate;

/**
 * Passo {@code certificate-policy}: etapas 2.5 e 2.6 do caso de uso de criação — política do
 * certificado folha na allowlist (OID completo, tipo e emissor), RSA 2048/4096 conforme o tipo,
 * {@code digitalSignature}, data mínima de emissão, validade no timestamp de referência e
 * identidade CPF/CNPJ. Escreve o atributo {@link #SIGNER_IDENTITY_KEY}.
 */
@StepId("certificate-policy")
public class CertificatePolicyStep implements SigningStep {

    public static final String SIGNER_IDENTITY_KEY = "signerIdentity";

    private final SafiraPolicyProperties policy;

    public CertificatePolicyStep(SafiraPolicyProperties policy) {
        this.policy = policy;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        X509Certificate[] chain = context.getCertificateChain().orElse(null);
        if (chain == null || chain.length < 2) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "Cadeia validada ausente; o step pkix-chain-validation deve precedê-lo.", context);
        }
        X509Certificate leaf = chain[0];
        long referenceTimestamp = context.getReferenceTimestamp();
        if (referenceTimestamp < leaf.getNotBefore().toInstant().getEpochSecond()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_YET_VALID,
                    "O certificado do signatário ainda não é válido no timestamp de referência.", context);
        }
        if (referenceTimestamp > leaf.getNotAfter().toInstant().getEpochSecond()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_EXPIRED,
                    "O certificado do signatário está expirado no timestamp de referência.", context);
        }
        ProfileResult result = IcpBrasilCertificateProfile.evaluate(leaf, chain[1],
                policy.acceptedCertificatePolicies(), policy.minCertIssueDate());
        return switch (result) {
            case ProfileResult.Rejected rejected ->
                    StepResult.failure(getName(), rejected.code(), rejected.diagnostics(), context);
            case ProfileResult.Eligible eligible -> StepResult.success(getName(), context.toBuilder()
                    .attribute(SIGNER_IDENTITY_KEY, eligible.identity())
                    .build());
        };
    }
}
