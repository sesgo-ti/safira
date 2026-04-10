package br.gov.go.saude.fhir.safira.steps.signing.tsa;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * Implementação HTTP do {@link TsaClient} para requisições RFC 3161.
 *
 * <p><b>TODO:</b> A integração HTTP real com TSA externa não está implementada nesta versão.
 * Requer:
 * <ul>
 *   <li>POST para {@code tsaUrl} com {@code Content-Type: application/timestamp-query}</li>
 *   <li>Corpo: {@code request.getEncoded()}</li>
 *   <li>Parse da resposta via {@code new TimeStampResponse(responseBytes)}</li>
 *   <li>Política de retry conforme configuração operacional</li>
 *   <li>Autenticação HTTP Basic opcional</li>
 * </ul>
 *
 * <p>Para integração com uma TSA ICP-Brasil real, consulte RFC 3161 §3.4.
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
