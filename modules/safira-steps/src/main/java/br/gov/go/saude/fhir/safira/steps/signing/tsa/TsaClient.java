/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.tsa;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Cliente para comunicação com uma TSA (Time Stamp Authority) conforme RFC 3161.
 *
 * <p>Abstração injetável para permitir testes com mocks e futura integração HTTP real.
 */
public interface TsaClient {

    /**
     * Envia um {@link TimeStampRequest} para a TSA e retorna a resposta.
     *
     * @param tsaUrl URL do serviço TSA
     * @param request requisição RFC 3161 assinada
     * @param timeoutSeconds timeout em segundos
     * @return resposta da TSA com o token
     * @throws TsaUnavailableException quando a TSA não responde dentro do timeout
     * @throws TsaInvalidResponseException quando a resposta é malformada ou indica falha
     */
    TimeStampResponse requestTimestamp(String tsaUrl, TimeStampRequest request, int timeoutSeconds)
            throws TsaUnavailableException, TsaInvalidResponseException;
}
