/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.tsa;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Implementação HTTP do {@link TsaClient} para requisições RFC 3161.
 *
 * <p>Não implementada: lança {@link TsaUnavailableException} em todas as chamadas.
 * Para integrar, fazer POST para {@code tsaUrl} com {@code Content-Type: application/timestamp-query},
 * corpo {@code request.getEncoded()}, e parsear a resposta via {@code new TimeStampResponse(bytes)}.
 */
public class HttpTsaClient implements TsaClient {

    @Override
    public TimeStampResponse requestTimestamp(String tsaUrl, TimeStampRequest request, int timeoutSeconds)
            throws TsaUnavailableException {
        throw new TsaUnavailableException(
                "Integração HTTP com TSA externa ainda não está implementada. "
                        + "Utilize uma implementação customizada de TsaClient ou aguarde a implementação futura.");
    }
}
