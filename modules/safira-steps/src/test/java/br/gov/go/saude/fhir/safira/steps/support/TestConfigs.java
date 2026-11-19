/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.support;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.VerificationProps;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TemporalPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TrustStoreRef;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicies;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/** Configurações válidas da política 0.2.0 para testes. */
public final class TestConfigs {

    private TestConfigs() {
    }

    public static SafiraOperationalConfigProperties operational(String tsaUrl) {
        return new SafiraOperationalConfigProperties(
                new VerificationProps(20, 20, 20, tsaUrl),
                new SecurityLimitsProps(1000, 52428800));
    }

    public static SafiraOperationalConfigProperties operational() {
        return operational(null);
    }

    /** Allowlist com as políticas A3 e SE-S emitidas pela AC da {@link PkiIcpSimulada}. */
    public static SafiraPolicyProperties policy(PkiIcpSimulada pki) {
        return policy(pki, null);
    }

    public static SafiraPolicyProperties policy(PkiIcpSimulada pki, TsaPolicies tsa) {
        return new SafiraPolicyProperties(
                List.of(new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3, pki.emissorSha256()),
                        new AcceptedCertificatePolicy("2.16.76.1.2.201.1", CertificateType.SE_S, pki.emissorSha256())),
                tsa,
                new TemporalPolicy(1751328000L));
    }

    /** Políticas TSA com a âncora informada gravada em PEM temporário. */
    public static TsaPolicies tsaPolicies(Path dir, String oid, long maxAccuracySeconds, X509Certificate anchor) {
        try {
            Path pem = Files.createTempFile(dir, "tsa", ".pem");
            Files.writeString(pem, "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(anchor.getEncoded())
                    + "\n-----END CERTIFICATE-----\n", StandardCharsets.US_ASCII);
            return new TsaPolicies("1.0.0", List.of(new TsaPolicy(oid, maxAccuracySeconds, new TrustStoreRef("file:" + pem))));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
