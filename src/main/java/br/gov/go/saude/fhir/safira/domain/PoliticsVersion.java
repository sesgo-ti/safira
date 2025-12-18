package br.gov.go.saude.fhir.safira.domain;

import lombok.Getter;

@Getter
public enum PoliticsVersion {
    BR_GO_SES_SEGURANCA_0_1_0("https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0");

    private final String url;

    PoliticsVersion(String url) {
        this.url = url;
    }
}
