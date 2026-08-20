/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.signing.ContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.JwsFinalStep;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.jades.JAdESUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Pipeline JAdES 2.0.0 encadeando os steps reais:
 * {@code jades-data-to-sign} → {@code crypto-signing} → {@code jades-assemble} →
 * {@code jades-extension} — com oráculo de conformidade (validador EU DSS + schema ETSI)
 * e TSA fake local (RFC 3161) para o nível B-T.
 */
class JadesSigningStepsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";
    private static final long REFERENCE_TIMESTAMP = 1755000000L;

    private static TestPki pki;
    private static TestPki.FakeTsa fakeTsa;

    @BeforeAll
    static void setup() {
        pki = TestPki.create();
        fakeTsa = pki.startFakeTsa();
    }

    @AfterAll
    static void tearDown() {
        fakeTsa.close();
    }

    @Test
    void estrategiaIatDeveProduzirJadesBBValidoSemUnprotectedHeader() throws Exception {
        String jws = runPipeline(TimestampStrategy.IAT);

        JsonNode root = MAPPER.readTree(jws);
        assertThat(root.get("signatures").get(0).has("header")).isFalse();

        assertThat(JAdESUtils.getInstance().validateAgainstSchema(jws)).isEmpty();
        assertThat(validateWithDss(jws)).isEqualTo(Indication.TOTAL_PASSED);
    }

    @Test
    void estrategiaTsaDeveProduzirJadesBTComSigTstDentroDeEtsiU() throws Exception {
        String jws = runPipeline(TimestampStrategy.TSA);

        JsonNode header = MAPPER.readTree(jws).get("signatures").get(0).get("header");
        assertThat(header).isNotNull();
        // etsiU deve ser o ÚNICO parâmetro do unprotected header (ETSI TS 119 182-1 §4)
        assertThat(header.properties()).hasSize(1);
        JsonNode etsiU = header.get("etsiU");
        assertThat(etsiU).isNotNull();
        assertThat(etsiU.isArray()).isTrue();
        assertThat(etsiU.size()).isGreaterThanOrEqualTo(1);

        // Componentes incorporados em base64url: o primeiro deve ser {"sigTst": {"tstTokens": [{"val": ...}]}}
        String firstComponent = new String(
                Base64.getUrlDecoder().decode(etsiU.get(0).asText()), StandardCharsets.UTF_8);
        JsonNode sigTst = MAPPER.readTree(firstComponent).get("sigTst");
        assertThat(sigTst).isNotNull();
        assertThat(sigTst.get("tstTokens").isArray()).isTrue();
        assertThat(sigTst.get("tstTokens").get(0).has("val")).isTrue();

        // iat permanece presente na estratégia TSA (B-T adiciona sigTst, não substitui o iat)
        JsonNode protectedHeader = decodeProtectedHeader(jws);
        assertThat(protectedHeader.get("iat").asLong()).isEqualTo(REFERENCE_TIMESTAMP);

        assertThat(JAdESUtils.getInstance().validateAgainstSchema(jws)).isEmpty();
        assertThat(validateWithDss(jws)).isEqualTo(Indication.TOTAL_PASSED);
    }

    @Test
    void estrategiaTsaComTsaIndisponivelDeveFalharComTsaUnavailable() throws Exception {
        SigningContext context = signedContext(TimestampStrategy.TSA, "http://127.0.0.1:1/tsa");

        StepResult<SigningContext> result = new JadesExtensionStep().execute(context);

        assertInstanceOf(StepResult.Failure.class, result);
        var failure = (StepResult.Failure<SigningContext>) result;
        assertThat(failure.code().getCode()).startsWith("TSA.");
    }

    // ------------------------------------------------------------------
    // Infra do teste
    // ------------------------------------------------------------------

    private String runPipeline(TimestampStrategy strategy) throws Exception {
        SigningContext context = signedContext(strategy, fakeTsa.url());

        StepResult<SigningContext> extended = new JadesExtensionStep().execute(context);
        assertInstanceOf(StepResult.Success.class, extended,
                () -> "jades-extension falhou: " + ((StepResult.Failure<?>) extended).diagnostics());

        return extended.context()
                .getAttribute(JwsFinalStep.JWS_FINAL_KEY, String.class)
                .orElseThrow();
    }

    /** Executa jades-data-to-sign → crypto-signing → jades-assemble e retorna o contexto resultante. */
    private SigningContext signedContext(TimestampStrategy strategy, String tsaUrl) throws Exception {
        SigningContext initial = baseContext(strategy, tsaUrl);

        StepResult<SigningContext> dataToSign = new JadesDataToSignStep().execute(initial);
        assertInstanceOf(StepResult.Success.class, dataToSign);

        StepResult<SigningContext> signed = new CryptoSigningStep().execute(dataToSign.context());
        assertInstanceOf(StepResult.Success.class, signed);

        StepResult<SigningContext> assembled = new JadesAssembleStep().execute(signed.context());
        assertInstanceOf(StepResult.Success.class, assembled);

        return assembled.context();
    }

    private SigningContext baseContext(TimestampStrategy strategy, String tsaUrl) throws Exception {
        var verification = new SafiraOperationalConfigProperties.VerificationProps(
                3600, 3600, 20, 20, 20, 3, 2, tsaUrl, null, null);
        var opConfig = new SafiraOperationalConfigProperties(verification, null, null, null, null);

        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest("payload-canonicalizado-teste".getBytes(StandardCharsets.UTF_8));
        String contentDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        return SigningContext.builder()
                .strategy(strategy)
                .referenceTimestamp(REFERENCE_TIMESTAMP)
                .policyIdentifierUri(POLICY_URI)
                .certificateChain(new X509Certificate[]{pki.leafCert, pki.caCert})
                .cryptoMaterial(new CryptoMaterial.PemMaterial(pki.leafKeyPemBase64(), null))
                .operationalConfig(opConfig)
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, contentDigest)
                .build();
    }

    private Indication validateWithDss(String jws) {
        var verifier = CertificateVerifiers.create(
                List.of(pki.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(
                        pki.ocspGoodFor(pki.leafCert), pki.ocspGoodFor(pki.tsaCert))),
                EvidenceRevocationSources.crlFromEvidence(List.of(pki.crl())));

        Reports reports = new JadesValidationService().validate(jws, verifier);
        String signatureId = reports.getSimpleReport().getFirstSignatureId();
        return reports.getSimpleReport().getIndication(signatureId);
    }

    private static JsonNode decodeProtectedHeader(String jws) throws Exception {
        JsonNode root = MAPPER.readTree(jws);
        String protectedB64 = root.get("signatures").get(0).get("protected").asText();
        return MAPPER.readTree(new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8));
    }
}
