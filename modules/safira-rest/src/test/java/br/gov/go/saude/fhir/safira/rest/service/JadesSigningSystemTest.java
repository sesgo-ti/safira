/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.CA_CERT;
import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.LEAF_CERT;
import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.LEAF_KEYS;
import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.TEST_CPF;
import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.toBase64;
import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.toPemBase64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Teste de sistema da política 2.0.0 (perfil JAdES via EU DSS): exercita o wiring Spring
 * completo (auto-configurações, YAML, registry) e verifica a estrutura JAdES do JWS.
 */
@SpringBootTest
class JadesSigningSystemTest {

    private static final long REFERENCE_TS = Instant.now().getEpochSecond();
    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";

    @MockitoBean
    TrustStoreService trustStoreService;

    @MockitoBean
    RevocationService revocationService;

    @Autowired
    SigningService signingService;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void configureMocks() {
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any()))
                .thenReturn(new RevocationStatus.Good("OCSP", new byte[64]));
    }

    @Test
    void devAssinarComPolitica200EProduzirEstruturaJades() throws Exception {
        PipelineResult<?> result = signingService.sign(buildSigningInput());

        assertTrue(result.isSuccess(),
                "Pipeline 2.0.0 falhou: " + (result.isSuccess() ? "" : result.getExceptionDetails()));
        assertInstanceOf(Signature.class, result.getValue());
        Signature signature = (Signature) result.getValue();

        assertEquals("application/jose", signature.sigFormat());
        assertEquals("urn:brasil:cpf", signature.who().identifier().system());
        assertEquals(TEST_CPF, signature.who().identifier().value());

        // Estrutura JAdES do JWS produzido
        JsonNode jws = mapper.readTree(new String(signature.data(), StandardCharsets.UTF_8));
        assertTrue(jws.has("payload"), "JWS General JSON Serialization requer payload");
        assertEquals(43, jws.get("payload").asText().length(), "payload = SHA-256 base64url sem padding");

        JsonNode signatureEntry = jws.get("signatures").get(0);
        assertTrue(signatureEntry.has("protected"));
        assertTrue(signatureEntry.has("signature"));
        assertFalse(signatureEntry.has("header"), "B-B (estratégia iat) não tem unprotected header");

        JsonNode header = mapper.readTree(new String(
                Base64.getUrlDecoder().decode(signatureEntry.get("protected").asText()), StandardCharsets.UTF_8));
        assertEquals("RS256", header.get("alg").asText());
        assertEquals(2, header.get("x5c").size());
        assertEquals(REFERENCE_TS, header.get("iat").asLong(), "iat incondicional (ETSI TS 119 182-1 §5.1.11)");
        // sigPId.id é objeto oId (§5.4.1): {"id": {"id": "<uri>"}}
        assertEquals(POLICY_URI, header.get("sigPId").get("id").get("id").asText());
    }

    private SigningInput buildSigningInput() throws Exception {
        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "bundle-jades",
                  "entry": [{
                    "fullUrl": "urn:uuid:22222222-2222-2222-2222-222222222222",
                    "resource": {
                      "resourceType": "Patient",
                      "id": "p1",
                      "name": [{"family": "Souza"}]
                    }
                  }]
                }
                """;

        String provenanceJson = """
                {
                  "resourceType": "Provenance",
                  "id": "prov-jades",
                  "target": [{"reference": "urn:uuid:22222222-2222-2222-2222-222222222222"}]
                }
                """;

        return new SigningInput(
                mapper.readTree(bundleJson),
                mapper.readTree(provenanceJson),
                new SigningInput.PemCryptoMaterial(toPemBase64(LEAF_KEYS), null),
                List.of(toBase64(LEAF_CERT), toBase64(CA_CERT)),
                REFERENCE_TS,
                "iat",
                POLICY_URI
        );
    }
}
