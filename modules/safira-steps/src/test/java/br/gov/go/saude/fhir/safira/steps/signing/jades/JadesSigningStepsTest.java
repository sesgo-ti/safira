/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Steps JAdES da política 0.2.0 em sequência: jades-data-to-sign → crypto-signing →
 * jades-assemble → jades-extension → tsa-token-verification, com TSA local (RFC 3161).
 */
class JadesSigningStepsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static TestPki.FakeTsa fakeTsa;
    private static SafiraPolicyProperties policy;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        fakeTsa = pki.startFakeTsa();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
    }

    @AfterAll
    static void tearDown() {
        fakeTsa.close();
    }

    @Test
    void shouldProduceJadesBaselineBWithoutHeaderForIatStrategy() throws Exception {
        String jws = jws(extend(signedContext(TimestampStrategy.IAT, fakeTsa.url())));

        assertThat(MAPPER.readTree(jws).get("signatures").get(0).has("header")).isFalse();
        assertThat(dssFormat(jws)).isEqualTo(SignatureLevel.JAdES_BASELINE_B);
    }

    @Test
    void shouldProduceJadesBaselineTWithClearEtsiUForTsaStrategy() throws Exception {
        StepResult<SigningContext> extended = extend(signedContext(TimestampStrategy.TSA, fakeTsa.url()));
        String jws = jws(extended);

        JsonNode etsiU = MAPPER.readTree(jws).get("signatures").get(0).get("header").get("etsiU");
        assertThat(etsiU).hasSize(1);
        assertThat(etsiU.get(0).get("sigTst").get("tstTokens").get(0).get("val").isTextual()).isTrue();
        assertThat(dssFormat(jws)).isEqualTo(SignatureLevel.JAdES_BASELINE_T);
        assertThat(extended.context().getAttribute(JadesExtensionStep.TSA_POLICY_OID_KEY, String.class))
                .contains(TestPki.TSA_POLICY_OID);
    }

    @Test
    void shouldFailWithTsaUnavailableWhenTsaIsUnreachable() throws Exception {
        StepResult<SigningContext> result = extend(signedContext(TimestampStrategy.TSA, "https://127.0.0.1:9/tsa"));

        assertThat(((StepResult.Failure<SigningContext>) result).code()).isEqualTo(SignatureExceptionCode.TSA_UNAVAILABLE);
    }

    @Test
    void shouldAcceptTimestampTokenAnchoredInTsaTrustStore() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(any(), anyCollection(), any()))
                .thenReturn(new ValidationResult.Valid(List.of(fakeTsa.tsaCert()), pki.caCert, List.of()));

        StepResult<SigningContext> result = new TsaTokenVerificationStep(validator, policy)
                .execute(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context());

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void shouldRejectTimestampTokenOutsideTsaTrustStore() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(any(), anyCollection(), any()))
                .thenReturn(new ValidationResult.Untrusted(PKIXReason.NO_TRUST_ANCHOR, "fora do trust store TSA"));

        StepResult<SigningContext> result = new TsaTokenVerificationStep(validator, policy)
                .execute(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context());

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldSkipTokenVerificationForIatStrategy() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);

        StepResult<SigningContext> result = new TsaTokenVerificationStep(validator, policy)
                .execute(extend(signedContext(TimestampStrategy.IAT, fakeTsa.url())).context());

        assertThat(result.isSuccess()).isTrue();
    }

    // ------------------------------------------------------------------

    private StepResult<SigningContext> extend(SigningContext context) {
        return new JadesExtensionStep(new JadesExtensionService(), policy).execute(context);
    }

    private static String jws(StepResult<SigningContext> result) {
        assertThat(result.isSuccess()).isTrue();
        return result.context().getAttribute(SigningKeys.JWS_FINAL, String.class).orElseThrow();
    }

    /** Executa jades-data-to-sign → crypto-signing → jades-assemble e retorna o contexto resultante. */
    private SigningContext signedContext(TimestampStrategy strategy, String tsaUrl) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("conteudo".getBytes(StandardCharsets.UTF_8));
        SigningContext initial = SigningContext.builder()
                .strategy(strategy)
                .referenceTimestamp(Instant.now().getEpochSecond())
                .policyIdentifierUri(Policy020.POLICY_URI)
                .certificateChain(new X509Certificate[]{pki.leafCert, pki.caCert})
                .cryptoMaterial(new CryptoMaterial.PemMaterial(pki.leafKeyPemBase64(), null))
                .operationalConfig(TestConfigs.operational(tsaUrl))
                .attribute(SigningKeys.CONTENT_DIGEST, Base64.getUrlEncoder().withoutPadding().encodeToString(hash))
                .build();

        StepResult<SigningContext> dataToSign = new JadesDataToSignStep().execute(initial);
        StepResult<SigningContext> signed = new CryptoSigningStep().execute(dataToSign.context());
        StepResult<SigningContext> assembled = new JadesAssembleStep().execute(signed.context());
        assertThat(assembled.isSuccess()).isTrue();
        return assembled.context();
    }

    private SignatureLevel dssFormat(String jws) {
        var verifier = CertificateVerifiers.create(List.of(pki.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspGoodFor(pki.leafCert), pki.ocspGoodFor(fakeTsa.tsaCert()))),
                EvidenceRevocationSources.crlFromEvidence(List.of(pki.crl())));
        Reports reports = new JadesValidationService().validate(jws, verifier);
        String id = reports.getSimpleReport().getFirstSignatureId();
        assertThat(reports.getSimpleReport().getIndication(id)).isEqualTo(Indication.TOTAL_PASSED);
        return reports.getSimpleReport().getSignatureFormat(id);
    }
}
