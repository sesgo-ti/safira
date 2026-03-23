package br.gov.go.saude.fhir.safira.engine.domain;

public enum TimestampStrategy {
    IAT("iat"),
    TSA("tsa");

    private final String value;

    TimestampStrategy(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
