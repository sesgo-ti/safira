package br.gov.go.saude.fhir.safira.steps.signing.tsa;

/**
 * Exceção lançada quando a TSA (Time Stamp Authority) não responde dentro do timeout
 * configurado ou há falha de rede ao tentar obter um carimbo de tempo.
 */
public class TsaUnavailableException extends Exception {

    public TsaUnavailableException(String message) {
        super(message);
    }

    public TsaUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
