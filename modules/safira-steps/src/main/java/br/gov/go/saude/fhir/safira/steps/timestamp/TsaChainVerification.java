/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.timestamp;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.certificate.PkixResults;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Cadeia do certificado TSA validada pelo PKIX da lib icpbrasil-truststore contra as âncoras
 * da política TSA selecionada (trust store separado do acervo ICP-Brasil do signatário).
 */
public final class TsaChainVerification {

    private TsaChainVerification() {
    }

    /** Política TSA configurada cujo OID é exatamente {@code TSTInfo.policy}. */
    public static Optional<TsaPolicy> selectPolicy(SafiraPolicyProperties policy, Inspection inspection) {
        return policy.tsaPolicyList().stream()
                .filter(p -> p.oid().equals(inspection.policyOid()))
                .findFirst();
    }

    /** Texto exato de {@code signatures[0].signature} (base do message imprint). */
    public static String signatureText(String jwsJson) {
        return LosslessJson.parseObject(jwsJson).array("signatures")
                .filter(a -> !a.items().isEmpty())
                .map(a -> a.items().getFirst())
                .filter(JsonObject.class::isInstance)
                .map(JsonObject.class::cast)
                .flatMap(s -> s.string("signature"))
                .orElseThrow(() -> new TimestampTokenException(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                        "JWS sem signatures[0].signature."));
    }

    public static Optional<PolicyViolation> verify(PkixCertificateValidator validator, Inspection inspection,
                                                   TsaPolicy tsaPolicy) {
        List<X509Certificate> anchors;
        try {
            anchors = TsaTrustStores.load(tsaPolicy.trustStore() == null ? null : tsaPolicy.trustStore().reference());
        } catch (IllegalArgumentException e) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, e.getMessage()));
        }
        List<X509Certificate> candidates = inspection.tokenCertificates().stream()
                .filter(c -> !c.equals(inspection.tsaCertificate()))
                .toList();
        ValidationResult result = validator.validate(inspection.tsaCertificate(), candidates,
                TrustMaterial.anchoredAt(anchors));
        return switch (result) {
            case ValidationResult.Valid ignored -> Optional.empty();
            case ValidationResult.Revoked revoked -> Optional.of(new PolicyViolation(
                    SignatureExceptionCode.TSA_CERTIFICATE_REVOKED,
                    "Certificado da cadeia TSA revogado: " + revoked.certificate().getSubjectX500Principal().getName()));
            case ValidationResult.RevocationUndetermined undetermined -> PkixResults.violation(undetermined);
            default -> Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED,
                    "Cadeia da TSA não termina em âncora do trust store da política " + tsaPolicy.oid()
                            + PkixResults.violation(result).map(v -> ": " + v.diagnostics()).orElse(".")));
        };
    }
}
