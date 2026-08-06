/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import br.gov.go.saude.fhir.safira.rest.dto.ValidationInput;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation.RevocationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static br.gov.go.saude.fhir.safira.rest.service.IcpBrasilCertificateFixture.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Teste de sistema que verifica o fluxo completo de assinatura e validação de um Bundle FHIR.
 *
 * <p>O que este teste não cobre (diferenças do cenário real):
 * <ul>
 *   <li><b>Âncora ICP-Brasil:</b> a CA é gerada em memória; no real, a cadeia termina em
 *       um certificado raiz da ICP-Brasil baixado da infraestrutura da ITI.</li>
 *   <li><b>Revogação:</b> {@link RevocationService} é mockado; no real, consultas OCSP e
 *       CRL são feitas às ACs emissoras via rede.</li>
 *   <li><b>Certificados:</b> auto-gerados com BouncyCastle; no real, são certificados
 *       ICP-Brasil emitidos por ACs credenciadas.</li>
 *   <li><b>Timestamp:</b> estratégia IAT com {@code Instant.now()}; no real, pode ser TSA
 *       com token RFC 3161 emitido por autoridade de carimbo de tempo.</li>
 *   <li><b>Conectividade:</b> sem acesso à rede; no real, o engine consome serviços externos
 *       (OCSP, CRL, TSA, download de âncoras ICP-Brasil).</li>
 *   <li><b>Camada HTTP:</b> os serviços são invocados diretamente; a serialização JSON,
 *       content-type negotiation e validação de beans da camada REST não são exercitados aqui.</li>
 * </ul>
 */
@SpringBootTest
class SignAndValidateSystemTest {

    private static final long REFERENCE_TS = Instant.now().getEpochSecond();
    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";

    @MockitoBean
    TrustStoreService trustStoreService;

    @MockitoBean
    RevocationService revocationService;

    @Autowired
    SigningService signingService;

    @Autowired
    ValidationService validationService;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void configureMocks() {
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        // DER fictício de 64 bytes: SHA-512 gera 64 bytes → Base64 = 88 chars
        // (tamanho exigido pelo step jws-headers-validation para digestValue de rRefs)
        when(revocationService.check(any(), any()))
                .thenReturn(new RevocationStatus.Good("OCSP", new byte[64]));
    }

    @Test
    void shouldSignBundleAndValidateTheProducedSignature() throws Exception {
        // 1. ASSINAR
        SigningInput signingInput = buildSigningInput();

        PipelineResult<?> signingResult = signingService.sign(signingInput);

        assertTrue(signingResult.isSuccess(),
                "Pipeline de assinatura falhou: " + signingResult.getExceptionDetails());
        assertInstanceOf(Signature.class, signingResult.getValue());

        Signature signature = (Signature) signingResult.getValue();

        assertNotNull(signature.data(), "data (JWS) não pode ser nulo");
        assertTrue(signature.data().length > 0, "data (JWS) não pode ser vazio");
        assertEquals("application/jose", signature.sigFormat());
        assertEquals("application/octet-stream", signature.targetFormat());
        assertNotNull(signature.when());
        assertEquals(REFERENCE_TS, signature.when().getEpochSecond());

        // Identificação do signatário extraída do SAN do certificado
        assertNotNull(signature.who());
        assertNotNull(signature.who().identifier());
        assertEquals("urn:brasil:cpf", signature.who().identifier().system());
        assertEquals(TEST_CPF, signature.who().identifier().value());

        // Tipo de assinatura (Author's Signature — código ISO)
        assertNotNull(signature.type());
        assertFalse(signature.type().isEmpty());
        assertEquals("1.2.840.10065.1.12.1.1", signature.type().getFirst().code());

        // 2. VALIDAR
        // Signature.data() contém os bytes do JWS JSON.
        // ValidationInput.signedDataBase64 = Base64 desses bytes.
        String signedDataBase64 = Base64.getEncoder().encodeToString(signature.data());

        ValidationInput validationInput = new ValidationInput(
                signedDataBase64,
                REFERENCE_TS,
                POLICY_URI,
                null,
                null
        );

        PipelineResult<OperationOutcome> validationResult = validationService.validate(validationInput);

        assertTrue(validationResult.isSuccess(),
                "Pipeline de validação falhou: " + validationResult.getExceptionDetails());

        // 3. VERIFICAR OUTCOME
        OperationOutcome outcome = validationResult.getValue();
        assertEquals("OperationOutcome", outcome.resourceType());
        assertFalse(outcome.issue().isEmpty());

        OperationOutcome.Issue successIssue = outcome.issue().get(0);
        assertEquals("information", successIssue.severity());
        assertEquals("informational", successIssue.code());
        assertFalse(successIssue.details().coding().isEmpty());
        assertEquals(SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                successIssue.details().coding().get(0).code());

        // O diagnóstico confirma política e algoritmo usados
        assertNotNull(successIssue.diagnostics());
        assertTrue(successIssue.diagnostics().contains(POLICY_URI),
                "diagnostics deve referenciar a URI da política: " + successIssue.diagnostics());
        assertTrue(successIssue.diagnostics().contains("RS256"),
                "diagnostics deve indicar o algoritmo de assinatura: " + successIssue.diagnostics());
    }

    private SigningInput buildSigningInput() throws Exception {
        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "bundle-system-test",
                  "entry": [{
                    "fullUrl": "urn:uuid:33333333-3333-3333-3333-333333333333",
                    "resource": {
                      "resourceType": "Patient",
                      "id": "p1",
                      "name": [{"family": "Oliveira"}]
                    }
                  }]
                }
                """;
        String provenanceJson = """
                {
                  "resourceType": "Provenance",
                  "id": "prov-system-test",
                  "target": [{"reference": "urn:uuid:33333333-3333-3333-3333-333333333333"}]
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
