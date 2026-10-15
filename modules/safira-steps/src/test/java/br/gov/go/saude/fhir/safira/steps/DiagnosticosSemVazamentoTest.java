/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.FramedContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesAssembleStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesDataToSignStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesExtensionStep;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Detalhes internos de exceções (JVM, bibliotecas) ficam no log do servidor, nunca nos diagnostics. */
class DiagnosticosSemVazamentoTest {

    private static final String INTERNO = "DETALHE-INTERNO-SECRETO";

    @TempDir
    static Path tempDir;
    private static PkiIcpSimulada pki;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
    }

    private static String diagnostics(StepResult<?> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<?>) result).diagnostics();
    }

    private static SigningContext assembleContext(String signature) {
        return SigningContext.builder()
                .attribute(JadesDataToSignStep.JADES_SESSION_KEY, new JadesSigningSession(new JAdESSignatureParameters(), new byte[0]))
                .attribute(CryptoSigningStep.SIGNATURE_KEY, signature)
                .build();
    }

    private static SigningContext dataToSignContext(String contentDigest) {
        return SigningContext.builder()
                .certificateChain(pki.cadeia().toArray(X509Certificate[]::new))
                .attribute(SigningKeys.CONTENT_DIGEST, contentDigest)
                .build();
    }

    @Test
    void shouldNotLeakInternalMessageWhenJadesAssembleFailsUnexpectedly() {
        JadesSigningService service = mock(JadesSigningService.class);
        when(service.sign(any(), any())).thenThrow(new IllegalStateException(INTERNO));

        assertThatThrownBy(() -> new JadesAssembleStep(service).execute(assembleContext("AAAA")))
                .isInstanceOfSatisfying(StepException.class, e -> {
                    assertThat(e.getDiagnostics()).doesNotContain(INTERNO);
                    assertThat(e.getCode()).isEqualTo(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED);
                });
    }

    @Test
    void shouldNotLeakDecoderMessageWhenJadesAssembleSignatureIsNotBase64Url() throws Exception {
        String diagnostics = diagnostics(new JadesAssembleStep(mock(JadesSigningService.class))
                .execute(assembleContext("***")));

        assertThat(diagnostics).doesNotContain("Illegal");
    }

    @Test
    void shouldNotLeakInternalMessageWhenJadesDataToSignFailsUnexpectedly() {
        JadesSigningService service = mock(JadesSigningService.class);
        when(service.newSession(any())).thenThrow(new IllegalStateException(INTERNO));

        assertThatThrownBy(() -> new JadesDataToSignStep(service).execute(dataToSignContext("A".repeat(43))))
                .isInstanceOfSatisfying(StepException.class, e -> {
                    assertThat(e.getDiagnostics()).doesNotContain(INTERNO);
                    assertThat(e.getCode()).isEqualTo(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED);
                });
    }

    @Test
    void shouldNotLeakDecoderMessageWhenJadesDataToSignDigestIsNotBase64Url() throws Exception {
        String diagnostics = diagnostics(new JadesDataToSignStep(mock(JadesSigningService.class))
                .execute(dataToSignContext("***")));

        assertThat(diagnostics).doesNotContain("Illegal");
    }

    @Test
    void shouldNotLeakInternalMessageWhenJadesExtensionFailsUnexpectedly() throws Exception {
        JadesExtensionService service = mock(JadesExtensionService.class);
        when(service.extendToBaselineT(any(), any())).thenThrow(new IllegalStateException(INTERNO));

        assertThat(diagnostics(extension(service))).doesNotContain(INTERNO);
    }

    @Test
    void shouldNotLeakInternalMessageWhenTsaIsUnavailable() throws Exception {
        JadesExtensionService service = mock(JadesExtensionService.class);
        when(service.extendToBaselineT(any(), any())).thenThrow(new DSSExternalResourceException(INTERNO));

        assertThat(diagnostics(extension(service))).doesNotContain(INTERNO);
    }

    private static StepResult<SigningContext> extension(JadesExtensionService service) throws Exception {
        var policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, pki.raiz()));
        return new JadesExtensionStep(service, policy).execute(SigningContext.builder()
                .strategy(TimestampStrategy.TSA)
                .operationalConfig(TestConfigs.operational("https://tsa.exemplo.invalid/tsa"))
                .attribute(SigningKeys.JWS_FINAL, "{}")
                .build());
    }

    @Test
    void shouldNotLeakInternalMessageWhenFramedContentDigestFailsUnexpectedly() {
        // sem bundle nem provenance: a NullPointerException da JVM não pode chegar ao diagnóstico
        String diagnostics = diagnostics(new FramedContentDigestStep().execute(SigningContext.builder().build()));

        assertThat(diagnostics).doesNotContain("null");
    }

    @Test
    void shouldNotLeakDecoderMessageWhenTimestampTokenIsNotBase64() {
        String jws = "{\"signatures\":[{\"header\":{\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":\"***\"}]}}]}}]}";

        assertThatThrownBy(() -> TimestampTokenInspector.tokenFromJws(jws))
                .isInstanceOfSatisfying(TimestampTokenException.class, e -> assertThat(e.getMessage()).doesNotContain("Illegal"));
    }
}
