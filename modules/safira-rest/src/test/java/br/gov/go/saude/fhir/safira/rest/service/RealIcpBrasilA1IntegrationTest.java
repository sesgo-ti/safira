/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Base64;
import java.util.Enumeration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integração com certificado ICP-Brasil A1 real (PKCS#12) e acervo real do ITI (bootstrap da lib
 * icpbrasil-truststore): a política 0.2.0 aceita apenas A3, A4, SE-S e SE-H (C16), então a
 * pipeline deve recusar o A1 no step {@code certificate-policy} — o que só ocorre depois de o
 * PKIX real (cadeia via AIA, âncora do acervo, revogação OCSP/CRL) aprovar o certificado.
 *
 * <p>Ignorado sem {@code -Dpfx.path} e {@code -Dpfx.password}. Execução:
 * <pre>
 * ./mvnw -Pintegration-tests test -pl modules/safira-rest -am \
 *     -Dtest=RealIcpBrasilA1IntegrationTest -Dsurefire.failIfNoSpecifiedTests=false \
 *     -Dpfx.path=/caminho/cert.pfx -Dpfx.password=senha
 * </pre>
 */
@Tag("integration")
@EnabledIfSystemProperty(named = "pfx.path", matches = ".+")
@SpringBootTest(properties = {
        "icpbrasil-truststore.bootstrap.enabled=true",
        "icpbrasil-truststore.scheduling.enabled=false",
        "icpbrasil-truststore.filesystem.base-dir=target/icpbrasil-truststore-it",
        // Allowlist fictícia (A3): o A1 real não pode corresponder a ela
        "safira.policy.accepted-certificate-policies[0].oid=2.16.76.1.2.3.1",
        "safira.policy.accepted-certificate-policies[0].type=A3",
        "safira.policy.accepted-certificate-policies[0].issuer-sha256=0000000000000000000000000000000000000000000000000000000000000000"
})
class RealIcpBrasilA1IntegrationTest {

    static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";

    @Autowired
    SigningService signingService;

    @Test
    void shouldRejectA1ByPolicyAfterRealPkixValidation() throws Exception {
        String pfxPath = System.getProperty("pfx.path");
        String pfxPassword = System.getProperty("pfx.password");
        Assumptions.assumeTrue(pfxPath != null && pfxPassword != null,
                "Teste ignorado: defina -Dpfx.path e -Dpfx.password para executar com certificado real");

        byte[] pfx = Files.readAllBytes(Path.of(pfxPath));
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfx), pfxPassword.toCharArray());
        String alias = firstKeyAlias(keyStore);
        String leaf = Base64.getEncoder().encodeToString(keyStore.getCertificate(alias).getEncoded());

        String body = "{\"bundle\":" + example("bundle.json")
                + ",\"provenance\":" + example("provenance.json")
                + ",\"signerCryptoMaterial\":{\"type\":\"PKCS12\",\"contentBase64\":\"" + Base64.getEncoder().encodeToString(pfx)
                + "\",\"password\":\"" + pfxPassword.replace("\\", "\\\\").replace("\"", "\\\"") + "\",\"alias\":\"" + alias + "\"}"
                + ",\"certificateChain\":[\"" + leaf + "\"]"
                + ",\"referenceTimestamp\":" + Instant.now().getEpochSecond()
                + ",\"strategy\":\"iat\",\"policyIdentifierUri\":\"" + POLICY_URI + "\"}";

        PipelineResult<?> result = signingService.sign(body);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getExceptionDetails().issue().getFirst().details().coding().getFirst().code())
                .isEqualTo("CERT.NOT-ICP-BRASIL");
    }

    private static String example(String name) throws Exception {
        return Files.readString(Path.of("src/test/resources/examples/politica-0.2.0/" + name), StandardCharsets.UTF_8);
    }

    private static String firstKeyAlias(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException("Nenhuma chave privada encontrada no PKCS#12.");
    }
}
