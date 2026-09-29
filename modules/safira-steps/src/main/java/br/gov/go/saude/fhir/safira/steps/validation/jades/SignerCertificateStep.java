/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import br.gov.go.saude.fhir.safira.steps.certificate.ProfileResult;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code signer-certificate}: seções 4.1 e 4.2 do caso de uso de validação — raiz de
 * {@code x5c} idêntica a uma âncora do acervo, política/tipo/chave/identidade do certificado
 * folha, correspondência com {@code Signature.who} e coerência de {@code Signature.when},
 * {@code iat}, timestamp de referência e validade da folha. Escreve
 * {@link ValidationKeys#SIGNER_IDENTITY}.
 */
@StepId("signer-certificate")
public class SignerCertificateStep implements ValidationStep {

    private final SafiraPolicyProperties policy;
    private final TrustMaterialSource trustMaterialSource;

    public SignerCertificateStep(SafiraPolicyProperties policy, TrustMaterialSource trustMaterialSource) {
        this.policy = policy;
        this.trustMaterialSource = trustMaterialSource;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        List<X509Certificate> chain = context.getCertificateChain().orElse(List.of());
        if (chain.size() < 2) {
            return fail(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "x5c deve conter a cadeia completa até a raiz ICP-Brasil.", context);
        }
        if (!isTrustedAnchor(chain.getLast())) {
            return fail(SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "A última posição de x5c não corresponde (SHA-256 do DER) a uma âncora do acervo ICP-Brasil.", context);
        }
        X509Certificate leaf = chain.getFirst();
        ProfileResult profile = IcpBrasilCertificateProfile.evaluate(leaf, chain.get(1),
                policy.acceptedCertificatePolicies(), policy.minCertIssueDate());
        if (profile instanceof ProfileResult.Rejected rejected) {
            return fail(validationCode(rejected.code(), leaf), rejected.diagnostics(), context);
        }
        SignerIdentity identity = ((ProfileResult.Eligible) profile).identity();

        JsonObject who = context.getSignatureJson().object("who").flatMap(w -> w.object("identifier")).orElseThrow();
        if (!identity.system().equals(who.string("system").orElse(null))
                || !identity.value().equals(who.string("value").orElse(null))) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Signature.who.identifier não corresponde à identidade " + identity.type().label()
                            + " do certificado x5c[0].", context);
        }

        long iat = context.getAttribute(ValidationKeys.IAT, Long.class).orElseThrow();
        Optional<OffsetDateTime> when = parseInstant(context.getSignatureJson().string("when").orElse(""));
        if (when.isEmpty() || when.get().getNano() != 0 || when.get().toEpochSecond() != iat) {
            return fail(SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                    "Signature.when deve representar exatamente o mesmo segundo de iat.", context);
        }
        if (iat > context.getReferenceTimestamp()) {
            return fail(SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                    "iat é posterior ao timestamp de referência da validação.", context);
        }
        if (iat < leaf.getNotBefore().toInstant().getEpochSecond() || iat > leaf.getNotAfter().toInstant().getEpochSecond()) {
            return fail(SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD,
                    "iat está fora do período de validade do certificado do signatário.", context);
        }
        return StepResult.success(getName(), context.toBuilder().attribute(ValidationKeys.SIGNER_IDENTITY, identity).build());
    }

    private boolean isTrustedAnchor(X509Certificate root) {
        String rootSha256 = IcpBrasilCertificateProfile.sha256Hex(root);
        return trustMaterialSource.current().stream()
                .flatMap(trust -> trust.anchors().stream())
                .map(TrustAnchor::getTrustedCert)
                .anyMatch(anchor -> anchor != null && IcpBrasilCertificateProfile.sha256Hex(anchor).equals(rootSha256));
    }

    /** Códigos da validação (4.1) para as recusas do perfil, definidos com os da criação. */
    private static SignatureExceptionCode validationCode(SignatureExceptionCode signingCode, X509Certificate leaf) {
        return switch (signingCode) {
            case CERT_NOT_ICP_BRASIL, CERT_CHAIN_VALIDATION_FAILED -> SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
            case CERT_WEAK_KEY -> leaf.getPublicKey() instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= 2048
                    ? SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED
                    : SignatureExceptionCode.CERT_WEAK_KEY;
            default -> signingCode;
        };
    }

    private static Optional<OffsetDateTime> parseInstant(String value) {
        try {
            return Optional.of(OffsetDateTime.parse(value));
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
