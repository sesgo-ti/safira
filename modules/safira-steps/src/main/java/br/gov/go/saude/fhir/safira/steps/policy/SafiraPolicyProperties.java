/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Configuração da política 0.2.0 ({@code safira.policy.*}), entrada 8 dos casos de uso.
 *
 * @param acceptedCertificatePolicies allowlist de políticas de certificado folha (OID completo,
 *                                    tipo e SHA-256 do DER do emissor imediato)
 * @param tsaPolicies                 políticas TSA aceitas, obrigatórias na estratégia {@code tsa}
 * @param temporalPolicy              data mínima de emissão do certificado folha
 */
@ConfigurationProperties(prefix = "safira.policy")
public record SafiraPolicyProperties(
        List<AcceptedCertificatePolicy> acceptedCertificatePolicies,
        TsaPolicies tsaPolicies,
        TemporalPolicy temporalPolicy) {

    public static final long DEFAULT_MIN_CERT_ISSUE_DATE = 1751328000L;
    private static final long MIN_CERT_ISSUE_DATE_FLOOR = 1609459200L;
    private static final String OID = "^[0-2](\\.(0|[1-9]\\d*))+$";
    private static final String SEMVER = "^\\d+\\.\\d+\\.\\d+$";
    private static final String SHA256_HEX = "^[0-9a-f]{64}$";

    public SafiraPolicyProperties {
        acceptedCertificatePolicies = acceptedCertificatePolicies == null
                ? List.of() : List.copyOf(acceptedCertificatePolicies);
    }

    // DIVERGENCIA-IG D3: o IG não publica a allowlist; ela vem da configuração e é obrigatória
    public record AcceptedCertificatePolicy(String oid, CertificateType type, String issuerSha256) {
    }

    public record TsaPolicies(String version, List<TsaPolicy> policies) {

        public TsaPolicies {
            policies = policies == null ? List.of() : List.copyOf(policies);
        }
    }

    public record TsaPolicy(String oid, Long maxAccuracySeconds, TrustStoreRef trustStore) {
    }

    public record TrustStoreRef(String reference) {
    }

    public record TemporalPolicy(Long minCertIssueDate) {
    }

    /** Problema de configuração com o código do IG (criar 1.11 / validar 0). */
    public record ConfigViolation(SignatureExceptionCode code, String diagnostics) {
    }

    public long minCertIssueDate() {
        return Optional.ofNullable(temporalPolicy)
                .map(TemporalPolicy::minCertIssueDate)
                .orElse(DEFAULT_MIN_CERT_ISSUE_DATE);
    }

    public List<TsaPolicy> tsaPolicyList() {
        return tsaPolicies == null ? List.of() : tsaPolicies.policies();
    }

    /**
     * Violações de configuração; vazia se a configuração é válida.
     *
     * @param tsaRequired verdadeiro quando a operação exige políticas TSA (estratégia {@code tsa}
     *                    na criação ou assinatura JAdES-B-T na validação)
     */
    public List<ConfigViolation> violations(boolean tsaRequired) {
        List<ConfigViolation> violations = new ArrayList<>();
        checkAllowlist(violations);
        long minDate = minCertIssueDate();
        if (minDate < MIN_CERT_ISSUE_DATE_FLOOR || minDate > Policy020.MAX_TIMESTAMP) {
            violations.add(new ConfigViolation(SignatureExceptionCode.CONFIG_CERT_MIN_DATE_OUT_OF_RANGE,
                    "safira.policy.temporal-policy.min-cert-issue-date fora de [1609459200, 4102444800]: " + minDate));
        }
        if (tsaRequired) {
            checkTsaPolicies(violations);
        }
        return List.copyOf(violations);
    }

    private void checkAllowlist(List<ConfigViolation> violations) {
        if (acceptedCertificatePolicies.isEmpty()) {
            violations.add(invalid("safira.policy.accepted-certificate-policies está vazia"));
            return;
        }
        Set<AcceptedCertificatePolicy> seen = new HashSet<>();
        for (AcceptedCertificatePolicy entry : acceptedCertificatePolicies) {
            if (!seen.add(entry)) {
                violations.add(invalid("Entrada duplicada na allowlist: " + entry.oid()));
            } else if (entry.type() == null || !entry.type().matchesBranch(entry.oid())) {
                violations.add(invalid("OID " + entry.oid() + " não tem sete arcos no ramo do tipo " + entry.type()));
            } else if (entry.issuerSha256() == null || !entry.issuerSha256().matches(SHA256_HEX)) {
                violations.add(invalid("issuer-sha256 do OID " + entry.oid()
                        + " deve ter 64 dígitos hexadecimais minúsculos"));
            }
        }
    }

    private void checkTsaPolicies(List<ConfigViolation> violations) {
        if (tsaPolicies == null || tsaPolicies.policies().isEmpty()) {
            violations.add(new ConfigViolation(SignatureExceptionCode.CONFIG_MISSING_PARAMETER,
                    "safira.policy.tsa-policies é obrigatório para carimbo do tempo"));
            return;
        }
        if (tsaPolicies.version() == null || !tsaPolicies.version().matches(SEMVER)) {
            violations.add(invalid("safira.policy.tsa-policies.version deve seguir major.minor.patch"));
        }
        Set<String> oids = new HashSet<>();
        for (TsaPolicy policy : tsaPolicies.policies()) {
            if (policy.oid() == null || !policy.oid().matches(OID) || !oids.add(policy.oid())) {
                violations.add(new ConfigViolation(SignatureExceptionCode.CONFIG_TSA_OID_INVALID,
                        "OID de política TSA inválido ou duplicado: " + policy.oid()));
                continue;
            }
            if (policy.maxAccuracySeconds() == null || policy.maxAccuracySeconds() <= 0) {
                violations.add(invalid("max-accuracy-seconds da política TSA " + policy.oid() + " deve ser positivo"));
                continue;
            }
            try {
                TsaTrustStores.load(policy.trustStore() == null ? null : policy.trustStore().reference());
            } catch (IllegalArgumentException e) {
                violations.add(new ConfigViolation(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                        "Trust store da política TSA " + policy.oid() + ": " + e.getMessage()));
            }
        }
    }

    private static ConfigViolation invalid(String diagnostics) {
        return new ConfigViolation(SignatureExceptionCode.CONFIG_INVALID_PARAMETER, diagnostics);
    }
}
