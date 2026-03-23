package br.gov.go.saude.fhir.safira.engine.domain;

public class SafiraException extends RuntimeException {
    private final String code;
    private final String description;

    public SafiraException(String code, String description) {
        super(description != null ? code + ": " + description : code);
        this.code = code;
        this.description = description;
    }

    public SafiraException(String code, String description, Throwable cause) {
        super(description != null ? code + ": " + description : code, cause);
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
