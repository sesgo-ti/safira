package br.gov.go.saude.fhir.safira.app;

import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class VersionsService {
    public static Set<String> getSupportedVersions() {
        return Set.of("https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0");
    }
}
