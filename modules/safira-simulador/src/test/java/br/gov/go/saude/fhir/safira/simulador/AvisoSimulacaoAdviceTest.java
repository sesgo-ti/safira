/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.rest.api.SignatureController;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.HandlerMapping;

import static org.assertj.core.api.Assertions.assertThat;

class AvisoSimulacaoAdviceTest {

    private final AvisoSimulacaoAdvice advice = new AvisoSimulacaoAdvice();

    private static OperationOutcome sucesso() {
        return OperationOutcome.createSignatureError(SignatureExceptionCode.VALIDATION_SUCCESS.getSeverity(),
                "informational", SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                SignatureExceptionCode.VALIDATION_SUCCESS.getDisplay(), "ok");
    }

    private Object escrever(Object corpo, String uri, String padrao, int status) {
        MockHttpServletRequest requisicao = new MockHttpServletRequest("POST", uri);
        if (padrao != null) {
            requisicao.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, padrao);
        }
        MockHttpServletResponse resposta = new MockHttpServletResponse();
        resposta.setStatus(status);
        return advice.beforeBodyWrite(corpo, null, MediaType.APPLICATION_JSON, StringHttpMessageConverter.class,
                new ServletServerHttpRequest(requisicao), new ServletServerHttpResponse(resposta));
    }

    private Object escrever(Object corpo, String caminho, int status) {
        return escrever(corpo, caminho, caminho, status);
    }

    @Test
    void shouldAppendSimulationIssueWhenValidationSucceeds() {
        OperationOutcome original = sucesso();

        OperationOutcome marcado = (OperationOutcome) escrever(original, "/validar", 200);

        assertThat(marcado.issue()).hasSize(original.issue().size() + 1);
        assertThat(marcado.issue().getFirst()).isEqualTo(original.issue().getFirst());
        assertThat(marcado.issue().getLast().details().text())
                .isEqualTo(AvisoSimulacaoAdvice.TEXTO);
    }

    @Test
    void shouldAppendSimulationIssueWhenServletPathPrefixesValidar() {
        OperationOutcome original = sucesso();

        OperationOutcome marcado = (OperationOutcome) escrever(original, "/api/validar", "/validar", 200);

        assertThat(marcado.issue()).hasSize(original.issue().size() + 1);
    }

    @Test
    void shouldKeepBodyWhenUriEndsWithValidarButMappingDiffers() {
        OperationOutcome original = sucesso();

        assertThat(escrever(original, "/validar", "/outro", 200)).isSameAs(original);
    }

    @Test
    void shouldKeepBodyWhenNoMappingPatternIsPresent() {
        OperationOutcome original = sucesso();

        assertThat(escrever(original, "/validar", null, 200)).isSameAs(original);
    }

    @Test
    void shouldKeepBodyWhenValidationFails() {
        OperationOutcome original = sucesso();

        assertThat(escrever(original, "/validar", 422)).isSameAs(original);
    }

    @Test
    void shouldKeepBodyWhenPathIsNotValidar() {
        OperationOutcome original = sucesso();

        assertThat(escrever(original, "/assinar", 200)).isSameAs(original);
    }

    @Test
    void shouldKeepBodyWhenBodyIsNotOperationOutcome() {
        String original = "{\"signature\":{}}";

        assertThat(escrever(original, "/validar", 200)).isSameAs(original);
    }

    @Test
    void shouldTargetSafiraApiControllerWhenScopingAdvice() throws Exception {
        assertThat(SignatureController.class.getPackageName()).isEqualTo(AvisoSimulacaoAdvice.PACOTE_API);
        assertThat(SignatureController.class.getMethod("validate", HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value()).containsExactly(AvisoSimulacaoAdvice.PADRAO);
    }
}
