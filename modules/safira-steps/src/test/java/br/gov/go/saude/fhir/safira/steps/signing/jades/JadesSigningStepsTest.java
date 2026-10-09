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
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSourceFactory;
import br.gov.go.saude.fhir.safira.testkit.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.TsaHttpLocal;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TrustStoreRef;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicies;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.fhir.safira.steps.support.FonteDeTeste;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Steps JAdES da política 0.2.0 em sequência: jades-data-to-sign → crypto-signing →
 * jades-assemble → jades-extension → tsa-token-verification, com TSA local (RFC 3161).
 */
class JadesSigningStepsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    static Path tempDir;
    private static PkiIcpSimulada pki;
    private static TsaHttpLocal fakeTsa;
    private static SafiraPolicyProperties policy;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        fakeTsa = pki.iniciarTsaHttp();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, pki.raiz()));
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
                .contains(PkiIcpSimulada.POLITICA_TSA);
    }

    @Test
    void shouldFailWithTsaUnavailableWhenTsaIsUnreachable() throws Exception {
        StepResult<SigningContext> result = extend(signedContext(TimestampStrategy.TSA, "https://127.0.0.1:9/tsa"));

        assertThat(((StepResult.Failure<SigningContext>) result).code()).isEqualTo(SignatureExceptionCode.TSA_UNAVAILABLE);
    }

    @Test
    void shouldUseInjectedTspSourceWhenStrategyIsTsa() throws Exception {
        List<String> pedidos = new ArrayList<>();
        TspSourceFactory emMemoria = (url, timeout, oid) -> {
            pedidos.add(url + "|" + oid);
            return pki.fonteTsp();
        };

        String jws = jws(new JadesExtensionStep(new JadesExtensionService(), policy, emMemoria)
                .execute(signedContext(TimestampStrategy.TSA, "https://tsa.invalid/tsa")));

        assertThat(dssFormat(jws)).isEqualTo(SignatureLevel.JAdES_BASELINE_T);
        assertThat(pedidos).containsExactly("https://tsa.invalid/tsa|" + PkiIcpSimulada.POLITICA_TSA);
    }

    /** Contexto com o snapshot que {@code pkix-chain-validation} guardaria para o acervo de teste. */
    private static SigningContext comSnapshot(SigningContext context) {
        return context.toBuilder().attribute(SigningKeys.ACERVO,
                SignedArtifactFixture.acervo(FonteDeTeste.com(pki.raiz(), pki.ac()))).build();
    }

    /** Verificador do DSS offline sobre o acervo de teste, com OCSP GOOD para qualquer certificado. */
    private static VerificadoresDss verifiers(RevocationSource<OCSP> ocsp) {
        return new VerificadoresDss(FonteDeTeste.com(pki.raiz(), pki.ac()),
                CertificateVerifierFactory.offline(ocsp, null));
    }

    @Test
    void shouldAcceptTimestampTokenAnchoredInTsaTrustStore() throws Exception {
        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(pki.fonteOcsp()), policy)
                .execute(comSnapshot(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context()));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void shouldFailWhenAcervoSnapshotIsMissing() throws Exception {
        SigningContext semSnapshot = extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context();

        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(pki.fonteOcsp()), policy)
                .execute(semSnapshot);

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldUseSameAcervoGenerationAcrossSigningSteps() throws Exception {
        AcervoDeConfianca capturado = SignedArtifactFixture.acervo(FonteDeTeste.com(pki.raiz(), pki.ac()));
        SigningContext context = extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context().toBuilder()
                .attribute(SigningKeys.ACERVO, capturado).build();
        VerificadoresDss mudou = new VerificadoresDss(
                (FonteDeConfianca) Optional::empty,
                CertificateVerifierFactory.offline(pki.fonteOcsp(), null));

        assertThat(new TsaTokenVerificationStep(mudou, policy).execute(context).isSuccess()).isTrue();
    }

    @Test
    void shouldNotLeakTrustStoreReferenceWhenTsaTrustStoreIsUnreadable() throws Exception {
        SafiraPolicyProperties broken = TestConfigs.policy(pki, new TsaPolicies("1.0.0", List.of(new TsaPolicy(
                PkiIcpSimulada.POLITICA_TSA, 1L, new TrustStoreRef("file:/segredo-caminho/ausente.pem")))));

        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(pki.fonteOcsp()), broken)
                .execute(comSnapshot(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context()));

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
        assertThat(((StepResult.Failure<SigningContext>) result).diagnostics()).doesNotContain("segredo-caminho");
    }

    @Test
    void shouldRejectTimestampTokenOutsideTsaTrustStore() throws Exception {
        SafiraPolicyProperties otherAnchor = TestConfigs.policy(pki,
                TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, PkiIcpSimulada.criar().raiz()));

        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(pki.fonteOcsp()), otherAnchor)
                .execute(comSnapshot(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context()));

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldRejectTimestampTokenWhenTsaIsRevoked() throws Exception {
        RevocationSource<OCSP> tsaRevoked = EvidenceRevocationSources.ocspPorCertificado(certificate -> certificate.equals(fakeTsa.certificado())
                ? pki.ocspRevogado(certificate)
                : pki.ocspBom(certificate));

        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(tsaRevoked), policy)
                .execute(comSnapshot(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context()));

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.TSA_CERTIFICATE_REVOKED);
    }

    @Test
    void shouldRejectTimestampTokenWhenTsaIssuingCaIsRevoked() throws Exception {
        RevocationSource<OCSP> caRevoked = EvidenceRevocationSources.ocspPorCertificado(pki.respostasComAcRevogada());

        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(caRevoked), policy)
                .execute(comSnapshot(extend(signedContext(TimestampStrategy.TSA, fakeTsa.url())).context()));

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.TSA_CERTIFICATE_REVOKED);
        assertThat(((StepResult.Failure<SigningContext>) result).diagnostics()).contains("/REVOKED_CA_NO_POE");
    }

    @Test
    void shouldSkipTokenVerificationForIatStrategy() throws Exception {
        StepResult<SigningContext> result = new TsaTokenVerificationStep(verifiers(pki.fonteOcsp()), policy)
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
                .certificateChain(pki.cadeia().toArray(X509Certificate[]::new))
                .cryptoMaterial(new CryptoMaterial.PemMaterial(pki.chavePrivadaSignatarioPemBase64(), null))
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
        var verifier = CertificateVerifierFactory.offline(
                        EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspBom(pki.signatario()),
                                pki.ocspBom(pki.ac()), pki.ocspBom(fakeTsa.certificado()))),
                        EvidenceRevocationSources.crlFromEvidence(List.of(pki.lcr())))
                .create(CertificateVerifierFactory.acervo(List.of(pki.raiz()), List.of(pki.ac())), List.of());
        Reports reports = new JadesValidationService().validate(jws, verifier);
        String id = reports.getSimpleReport().getFirstSignatureId();
        assertThat(reports.getSimpleReport().getIndication(id)).isEqualTo(Indication.TOTAL_PASSED);
        return reports.getSimpleReport().getSignatureFormat(id);
    }
}
