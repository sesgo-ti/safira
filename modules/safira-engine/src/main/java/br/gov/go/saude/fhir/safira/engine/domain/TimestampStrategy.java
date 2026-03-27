package br.gov.go.saude.fhir.safira.engine.domain;

import lombok.Getter;

@Getter
public enum TimestampStrategy {
    IAT("iat"),
    TSA("tsa");

    private final String value;

    TimestampStrategy(String value) {
        this.value = value;
    }
}
