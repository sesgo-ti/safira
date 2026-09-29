/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.support;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.VerificationProps;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
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
                new VerificationProps(3600, 3600, 20, 20, 20, 3, 2, tsaUrl, null, null),
                null,
                new SecurityLimitsProps(1000, 52428800, 10, 1751328000L, 4102444800L),
                null,
                null);
    }

    public static SafiraOperationalConfigProperties operational() {
        return operational(null);
    }

    /** Allowlist com a política A3 do {@link TestPki} emitida pela CA da PKI de teste. */
    public static SafiraPolicyProperties policy(TestPki pki) {
        return policy(pki, null);
    }

    public static SafiraPolicyProperties policy(TestPki pki, TsaPolicies tsa) {
        return new SafiraPolicyProperties(
                List.of(new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3, pki.issuerSha256()),
                        new AcceptedCertificatePolicy("2.16.76.1.2.201.1", CertificateType.SE_S, pki.issuerSha256())),
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
