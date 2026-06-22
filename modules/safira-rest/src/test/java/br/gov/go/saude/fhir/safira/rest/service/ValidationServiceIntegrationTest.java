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
 * Teste de integração E2E que executa a pipeline completa de assinatura (1.1.0) seguida
 * da pipeline de validação (1.1.0) via {@link SigningService} e {@link ValidationService}.
 *
 * <p>TrustStoreService e RevocationService são substituídos por mocks porque dependem de
 * infraestrutura externa (ICP-Brasil, OCSP/CRL) não disponível em CI. A âncora de confiança
 * é injetada via {@code @DynamicPropertySource} para que o step de validação da cadeia
 * reconheça o certificado raiz gerado em memória.
 */
@SpringBootTest
class ValidationServiceIntegrationTest {

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
        when(revocationService.check(any(), any()))
                .thenReturn(new RevocationStatus.Good("OCSP", new byte[64]));
    }

    @Test
    void shouldValidateSignatureProducedBySigningPipeline() throws Exception {
        PipelineResult<?> signingResult = signingService.sign(buildSigningInput());
        assertTrue(signingResult.isSuccess(),
                "Assinatura falhou: " + signingResult.getExceptionDetails());

        Signature signature = (Signature) signingResult.getValue();

        ValidationInput validationInput = new ValidationInput(
                Base64.getEncoder().encodeToString(signature.data()),
                REFERENCE_TS,
                POLICY_URI,
                null,
                null
        );

        PipelineResult<OperationOutcome> validationResult = validationService.validate(validationInput);
        assertTrue(validationResult.isSuccess(),
                "Validação falhou: " + validationResult.getExceptionDetails());

        OperationOutcome outcome = validationResult.getValue();
        assertEquals("OperationOutcome", outcome.resourceType());
        assertFalse(outcome.issue().isEmpty());

        OperationOutcome.Issue successIssue = outcome.issue().get(0);
        assertEquals("information", successIssue.severity());
        assertEquals("informational", successIssue.code());
        assertFalse(successIssue.details().coding().isEmpty());
        assertEquals(SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                successIssue.details().coding().get(0).code());
    }

    private SigningInput buildSigningInput() throws Exception {
        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "bundle-it-validation",
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
                  "id": "prov-it-validation",
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
