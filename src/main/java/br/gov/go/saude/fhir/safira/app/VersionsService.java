package br.gov.go.saude.fhir.safira.app;

import br.gov.go.saude.fhir.safira.domain.PoliticsVersion;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class VersionsService {
    public static Set<String> getVersionsAvailable() {
        return Arrays.stream(PoliticsVersion.values())
                .map(PoliticsVersion::getUrl)
                .collect(Collectors.toSet());
    }
}
