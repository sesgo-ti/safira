/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.CodigosDeSaida.Operacao;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CodigosDeSaidaTest {

    @ParameterizedTest
    @CsvSource({
            "FORMAT.JSON-MALFORMED, ASSINATURA, 3",
            "FORMAT.BUNDLE-MALFORMED, VALIDACAO, 3",
            "POLICY.URI-INVALID, ASSINATURA, 3",
            "CONFIG.INVALID-PARAMETER, ASSINATURA, 3",
            "SECURITY.BUNDLE-SIZE-LIMIT-EXCEEDED, VALIDACAO, 3",
            "CRYPTO.KEY-INACCESSIBLE, ASSINATURA, 3",
            "CRYPTO.PIN-INVALID, ASSINATURA, 3",
            "MIDDLEWARE.INVALID-CONFIG, ASSINATURA, 3",
            "DEVICE.TOKEN-NOT-FOUND, ASSINATURA, 3",
            "VALIDATION.INDETERMINATE, VALIDACAO, 4",
            "VALIDATION.TRY-LATER, VALIDACAO, 4",
            "REVOCATION.STATUS-UNKNOWN, VALIDACAO, 4",
            "REVOCATION.NO-CONNECTIVITY, ASSINATURA, 4",
            "CONFIG.TRUST-STORE-EMPTY, ASSINATURA, 4",
            "TSA.UNAVAILABLE, ASSINATURA, 4",
            "TSA.INVALID-RESPONSE, ASSINATURA, 4",
            "CACHE.UNAVAILABLE, VALIDACAO, 4",
            "NETWORK.ZIP-DOWNLOAD-FAILED, VALIDACAO, 4",
            "SYSTEM.TIMEOUT, VALIDACAO, 4",
            "CERT.REVOKED, ASSINATURA, 6",
            "CERT.NOT-ICP-BRASIL, VALIDACAO, 6",
            "CERT.EXPIRED, VALIDACAO, 6",
            "CRYPTO.HASH-VERIFICATION-FAILED, VALIDACAO, 6",
            "VALIDATION.SIGNATURE-VERIFICATION-FAILED, VALIDACAO, 6",
            "VALIDATION.POLICY-COMPLIANCE-FAILED, VALIDACAO, 6",
            "TSA.SIGNATURE-INVALID, VALIDACAO, 6",
            "TEMPORAL.IAT-OUT-OF-CERT-PERIOD, VALIDACAO, 6",
            "SECURITY.SIGNATURE-VALIDATION-REPLAY, VALIDACAO, 6",
            "FORMAT.JWS-MALFORMED, VALIDACAO, 6",
            "FORMAT.JADES-UNPROTECTED-HEADER-INVALID, VALIDACAO, 6",
            "FORMAT.JWK-INVALID, VALIDACAO, 6",
            "FORMAT.CERT-PEM-INVALID, VALIDACAO, 6",
            "FORMAT.JWS-MALFORMED, ASSINATURA, 3",
            "SYSTEM.MEMORY-EXHAUSTED, ASSINATURA, 1"
    })
    void shouldMapIgCodesToExitCodes(String codigo, Operacao operacao, int saida) {
        assertThat(CodigosDeSaida.de(outcome("error", codigo), operacao)).isEqualTo(saida);
    }

    @ParameterizedTest
    @EnumSource(Operacao.class)
    void shouldTreatUnknownCodeAsInconclusive(Operacao operacao) {
        assertThat(CodigosDeSaida.de(outcome("error", "DESCONHECIDO.QUALQUER"), operacao))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @Test
    void shouldUseFirstErrorIssueAndIgnoreInformationalIssues() {
        OperationOutcome sucessoMarcado = juntar(outcome("information", "VALIDATION.SUCCESS"),
                outcome("information", "VALIDATION.SUCCESS"));
        OperationOutcome falha = juntar(outcome("information", "VALIDATION.SUCCESS"), outcome("error", "CERT.REVOKED"));
        OperationOutcome duasFalhas = juntar(outcome("error", "CERT.REVOKED"), outcome("error", "REVOCATION.STATUS-UNKNOWN"));

        assertThat(CodigosDeSaida.de(sucessoMarcado, Operacao.VALIDACAO)).isEqualTo(CodigosDeSaida.SUCESSO);
        assertThat(CodigosDeSaida.de(falha, Operacao.VALIDACAO)).isEqualTo(CodigosDeSaida.REPROVADA);
        assertThat(CodigosDeSaida.de(duasFalhas, Operacao.VALIDACAO)).isEqualTo(CodigosDeSaida.REPROVADA);
    }

    @Test
    void shouldExitWithSuccessOnlyWithValidationSuccessCode() {
        assertThat(CodigosDeSaida.de(outcome("information", "VALIDATION.SUCCESS"), Operacao.VALIDACAO))
                .isEqualTo(CodigosDeSaida.SUCESSO);
    }

    @ParameterizedTest
    @EnumSource(Operacao.class)
    void shouldNotExitWithSuccessWhenOutcomeHasNoIssues(Operacao operacao) {
        assertThat(CodigosDeSaida.de(new OperationOutcome("OperationOutcome", null, List.of()), operacao))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
        assertThat(CodigosDeSaida.de(new OperationOutcome("OperationOutcome", null, null), operacao))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @ParameterizedTest
    @EnumSource(Operacao.class)
    void shouldNotExitWithSuccessWhenOutcomeHasOnlyWarnings(Operacao operacao) {
        OperationOutcome avisos = juntar(outcome("warning", "CERT.NEAR-EXPIRY"), outcome("information", "CACHE.STALE-BUT-VALID"));

        assertThat(CodigosDeSaida.de(avisos, operacao)).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @ParameterizedTest
    @EnumSource(Operacao.class)
    void shouldNotExitWithSuccessWhenIssueHasNoCoding(Operacao operacao) {
        OperationOutcome.Issue semCoding = new OperationOutcome.Issue("information", "informational", null, null, null);
        OperationOutcome.Issue erroSemCoding = new OperationOutcome.Issue("error", "processing", null, null, null);

        assertThat(CodigosDeSaida.de(new OperationOutcome("OperationOutcome", null, List.of(semCoding)), operacao))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
        assertThat(CodigosDeSaida.de(new OperationOutcome("OperationOutcome", null, List.of(erroSemCoding)), operacao))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @Test
    void shouldPreferErrorOverSuccessCodeWhenBothPresent() {
        OperationOutcome ambos = juntar(outcome("information", "VALIDATION.SUCCESS"), outcome("error", "CERT.REVOKED"));
        OperationOutcome sucessoComoErro = outcome("error", "VALIDATION.SUCCESS");

        assertThat(CodigosDeSaida.de(ambos, Operacao.VALIDACAO)).isEqualTo(CodigosDeSaida.REPROVADA);
        assertThat(CodigosDeSaida.de(sucessoComoErro, Operacao.VALIDACAO)).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @Test
    void shouldNotExitWithSuccessForSigningOutcome() {
        assertThat(CodigosDeSaida.de(outcome("information", "VALIDATION.SUCCESS"), Operacao.ASSINATURA))
                .isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @Test
    void shouldMapEveryCodeOfTheCodeSystem() {
        for (SignatureExceptionCode codigo : SignatureExceptionCode.values()) {
            for (Operacao operacao : Operacao.values()) {
                assertThat(CodigosDeSaida.de(outcome("error", codigo.getCode()), operacao))
                        .isIn(CodigosDeSaida.SUCESSO, CodigosDeSaida.ERRO_INTERNO, CodigosDeSaida.USO,
                                CodigosDeSaida.INCONCLUSIVO, CodigosDeSaida.REPROVADA);
            }
        }
    }

    private static OperationOutcome outcome(String severidade, String codigo) {
        return OperationOutcome.createSignatureError(severidade, "processing", codigo, "texto", "diagnóstico");
    }

    private static OperationOutcome juntar(OperationOutcome primeiro, OperationOutcome segundo) {
        List<OperationOutcome.Issue> issues = new ArrayList<>(primeiro.issue());
        issues.addAll(segundo.issue());
        return new OperationOutcome(primeiro.resourceType(), primeiro.id(), issues);
    }
}
