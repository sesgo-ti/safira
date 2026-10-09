/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class AvisoSimulacaoAdviceTest {

    private final AvisoSimulacaoAdvice advice = new AvisoSimulacaoAdvice();

    private static OperationOutcome sucesso() {
        return OperationOutcome.createSignatureError(SignatureExceptionCode.VALIDATION_SUCCESS.getSeverity(),
                "informational", SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                SignatureExceptionCode.VALIDATION_SUCCESS.getDisplay(), "ok");
    }

    private Object escrever(Object corpo, String caminho, int status) {
        MockHttpServletResponse resposta = new MockHttpServletResponse();
        resposta.setStatus(status);
        return advice.beforeBodyWrite(corpo, null, MediaType.APPLICATION_JSON, StringHttpMessageConverter.class,
                new ServletServerHttpRequest(new MockHttpServletRequest("POST", caminho)),
                new ServletServerHttpResponse(resposta));
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
}
