/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;
import org.springframework.web.util.UrlPathHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * Marca o {@code OperationOutcome} de sucesso (200) de {@code POST /validar} produzido no modo
 * simulação com uma issue informativa adicional, para que o resultado nunca seja confundido com uma
 * validação ICP-Brasil real. Registrado só quando {@code safira.simulacao.enabled=true}; o produto
 * ({@code safira-rest}) não conhece a simulação.
 */
@RestControllerAdvice
public class AvisoSimulacaoAdvice implements ResponseBodyAdvice<Object> {

    public static final String TEXTO = "SIMULAÇÃO — sem validade jurídica ICP-Brasil";

    static final String CAMINHO = "/validar";

    // DIVERGENCIA-IG: o CodeSystem não tem código próprio para simulação; a issue reutiliza
    // VALIDATION.SUCCESS (information) para manter o OperationOutcome conforme ao perfil.
    private static final OperationOutcome.Issue ISSUE = OperationOutcome.createSignatureError(
            SignatureExceptionCode.VALIDATION_SUCCESS.getSeverity(), "informational",
            SignatureExceptionCode.VALIDATION_SUCCESS.getCode(), TEXTO,
            "Modo simulação ativo (safira.simulacao.enabled=true): confiança em raízes próprias ("
                    + GeradorPkiSimulada.MARCA + ") no lugar do acervo ICP-Brasil.").issue().getFirst();

    private static final UrlPathHelper CAMINHOS = new UrlPathHelper();

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        if (body instanceof OperationOutcome outcome && validacao(request) && sucesso(response)) {
            return marcar(outcome);
        }
        return body;
    }

    private static boolean validacao(ServerHttpRequest request) {
        return request instanceof ServletServerHttpRequest servlet
                && CAMINHO.equals(CAMINHOS.getPathWithinApplication(servlet.getServletRequest()));
    }

    private static boolean sucesso(ServerHttpResponse response) {
        return response instanceof ServletServerHttpResponse servlet
                && servlet.getServletResponse().getStatus() == HttpStatus.OK.value();
    }

    /** Acrescenta a issue de simulação ao final das issues existentes. */
    static OperationOutcome marcar(OperationOutcome outcome) {
        List<OperationOutcome.Issue> issues = new ArrayList<>(outcome.issue());
        issues.add(ISSUE);
        return new OperationOutcome(outcome.resourceType(), outcome.id(), List.copyOf(issues));
    }
}
