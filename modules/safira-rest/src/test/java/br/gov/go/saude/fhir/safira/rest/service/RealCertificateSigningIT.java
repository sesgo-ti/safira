/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste E2E condicional com certificado PKCS#12 real.
 *
 * <p>Ignorado automaticamente quando as system properties {@code pfx.path} e
 * {@code pfx.password} não estão definidas. Execução:
 * <pre>
 * mvn test -pl modules/safira-rest \
 *     -Dtest=RealCertificateSigningIT \
 *     -Dpfx.path=/caminho/cert.pfx \
 *     -Dpfx.password=senha
 * </pre>
 */
@SpringBootTest
class RealCertificateSigningIT {

    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";

    @Autowired
    private SigningService signingService;

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    @Test
    void shouldSignBundleWithRealCertificate() throws Exception {
        String pfxPath = System.getProperty("pfx.path");
        String pfxPassword = System.getProperty("pfx.password");
        Assumptions.assumeTrue(pfxPath != null && pfxPassword != null,
                "Teste ignorado: defina -Dpfx.path e -Dpfx.password para executar com certificado real");

        byte[] pfxBytes = Files.readAllBytes(Path.of(pfxPath));
        String alias = findFirstKeyAlias(pfxBytes, pfxPassword);
        List<String> certChain = extractCertificateChain(pfxBytes, pfxPassword, alias);

        JsonNode bundle = loadResource("examples/bundle.json");
        JsonNode provenance = loadResource("examples/provenance.json");

        SigningInput input = new SigningInput(
                bundle,
                provenance,
                new SigningInput.Pkcs12CryptoMaterial(
                        Base64.getEncoder().encodeToString(pfxBytes),
                        pfxPassword,
                        alias),
                certChain,
                Instant.now().getEpochSecond(),
                "iat",
                POLICY_URI);

        PipelineResult<?> result = signingService.sign(input);

        assertTrue(result.isSuccess(),
                "Pipeline falhou: " + (result.isSuccess() ? "" : result.getExceptionDetails()));

        assertInstanceOf(Signature.class, result.getValue());
        Signature signature = (Signature) result.getValue();

        assertNotNull(signature.data());
        assertTrue(signature.data().length > 0);
        assertEquals("application/jose", signature.sigFormat());
        assertEquals("application/octet-stream", signature.targetFormat());
        assertNotNull(signature.when());
        assertNotNull(signature.who());
        assertNotNull(signature.who().identifier());
        assertNotNull(signature.type());
        assertFalse(signature.type().isEmpty());

        System.out.println("\n===== FHIR Signature =====");
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signature));
        System.out.println("==========================\n");
    }

    private JsonNode loadResource(String path) throws Exception {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(path)) {
            assertNotNull(is, "Recurso não encontrado no classpath: " + path);
            return mapper.readTree(is);
        }
    }

    private String findFirstKeyAlias(byte[] pfxBytes, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfxBytes), password.toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException("Nenhuma chave privada encontrada no PKCS#12.");
    }

    private List<String> extractCertificateChain(byte[] pfxBytes, String password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfxBytes), password.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("O alias '" + alias + "' não possui cadeia de certificados.");
        }
        List<String> result = new ArrayList<>();
        for (Certificate cert : chain) {
            result.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
        }
        return result;
    }
}
