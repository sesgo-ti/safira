package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class TestVersionsService {

    @Autowired
    VersionsService versionsService;

    @Test
    void getVersionsSupportedCorrectly() {
        Set<String> expectedSupportedVersions = Set.of(
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0",
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0"
        );

        assertEquals(expectedSupportedVersions, versionsService.getVersionsSupported());
    }
}
