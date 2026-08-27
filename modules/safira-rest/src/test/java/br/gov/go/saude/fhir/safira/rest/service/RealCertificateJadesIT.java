/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.OnlineRevocationSources;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.jades.JAdESUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste E2E condicional da política 2.0.0 (JAdES via EU DSS) com certificado PKCS#12 real
 * (ICP-Brasil A1), cobrindo assinatura e validação:
 *
 * <ol>
 *   <li><b>Assinatura</b>: pipeline completo da política 2.0.0 (trust-store real, resolução
 *       de cadeia, revogação OCSP/CRL reais, montagem JAdES pelo DSS);</li>
 *   <li><b>Validação estrutural</b>: JWS validado contra o schema oficial ETSI TS 119 182-1;</li>
 *   <li><b>Validação criptográfica e de cadeia</b>: validador do EU DSS (ETSI EN 319 102-1)
 *       com âncora na raiz ICP-Brasil do {@code x5c} e revogação online (AIA/CDP reais).</li>
 * </ol>
 *
 * <p>Execução (estratégia {@code iat} → JAdES-B-B):
 * <pre>
 * mvn test -pl modules/safira-rest \
 *     -Dtest=RealCertificateJadesIT \
 *     -Dpfx.path=/caminho/cert.pfx \
 *     -Dpfx.password=senha
 * </pre>
 *
 * <p>Com TSA real (estratégia {@code tsa} → JAdES-B-T; com target-level B-LT → LTV):
 * <pre>
 * mvn test -pl modules/safira-rest \
 *     -Dtest=RealCertificateJadesIT \
 *     -Dpfx.path=/caminho/cert.pfx \
 *     -Dpfx.password=senha \
 *     -Dtsa.url=https://freetsa.org/tsr \
 *     -Dsafira.jades.signing.target-level=B-LT
 * </pre>
 *
 * <p>Requer rede (revogação OCSP/CRL das ACs ICP-Brasil). A senha informada via linha de
 * comando fica no histórico do shell — prefira exportá-la em variável de ambiente ou
 * prefixar o comando com espaço (com {@code HIST_IGNORE_SPACE} ativo).
 */
@SpringBootTest(properties = {
        // O YAML de teste desliga o bootstrap (beans mockados nos demais testes);
        // aqui o trust-store REAL é necessário para chain-build/chain-validation.
        "truststore-icpbrasil.bootstrap.enabled=true",
        "truststore-icpbrasil.scheduling.enabled=false"
})
class RealCertificateJadesIT {

    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";

    @Autowired
    private SigningService signingService;

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    @Test
    void deveAssinarEValidarComCertificadoRealNaPolitica200() throws Exception {
        String pfxPath = System.getProperty("pfx.path");
        String pfxPassword = System.getProperty("pfx.password");
        Assumptions.assumeTrue(pfxPath != null && pfxPassword != null,
                "Teste ignorado: defina -Dpfx.path e -Dpfx.password para executar com certificado real");

        // ------------------------------------------------------------------
        // 1. ASSINAR com a política 2.0.0
        // ------------------------------------------------------------------
        byte[] pfxBytes = Files.readAllBytes(Path.of(pfxPath));
        String alias = findFirstKeyAlias(pfxBytes, pfxPassword);
        List<String> certChain = extractCertificateChain(pfxBytes, pfxPassword, alias);

        String tsaUrl = System.getProperty("tsa.url");
        String strategy = tsaUrl != null ? "tsa" : "iat";

        SigningInput input = new SigningInput(
                loadResource("examples/bundle.json"),
                loadResource("examples/provenance.json"),
                new SigningInput.Pkcs12CryptoMaterial(
                        Base64.getEncoder().encodeToString(pfxBytes),
                        pfxPassword,
                        alias),
                certChain,
                Instant.now().getEpochSecond(),
                strategy,
                POLICY_URI);

        PipelineResult<?> result = signingService.sign(input);

        assertTrue(result.isSuccess(),
                "Pipeline 2.0.0 falhou: " + (result.isSuccess() ? "" : result.getExceptionDetails()));
        Signature signature = (Signature) result.getValue();
        String jws = new String(signature.data(), StandardCharsets.UTF_8);

        System.out.println("\n===== FHIR Signature (política 2.0.0, estratégia " + strategy + ") =====");
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signature));
        System.out.println("\n===== JWS (JAdES) =====");
        System.out.println(jws);

        // ------------------------------------------------------------------
        // 2. VALIDAR estrutura contra o schema oficial ETSI TS 119 182-1
        // ------------------------------------------------------------------
        List<String> schemaViolations = JAdESUtils.getInstance().validateAgainstSchema(jws);
        assertTrue(schemaViolations.isEmpty(),
                "JWS não conforme ao schema ETSI: " + schemaViolations);

        // ------------------------------------------------------------------
        // 3. VALIDAR com o EU DSS (ETSI EN 319 102-1): âncora = raiz ICP-Brasil
        //    do x5c produzido; revogação = OCSP/CRL online (AIA/CDP reais)
        // ------------------------------------------------------------------
        List<X509Certificate> x5c = extractX5c(jws);
        X509Certificate icpBrasilRoot = x5c.getLast();

        var verifier = CertificateVerifiers.create(
                List.of(icpBrasilRoot),
                OnlineRevocationSources.ocsp(20),
                OnlineRevocationSources.crl(20));

        Reports reports = new JadesValidationService().validate(jws, verifier);
        SimpleReport simple = reports.getSimpleReport();
        String signatureId = simple.getFirstSignatureId();

        System.out.println("\n===== Validação DSS (ETSI EN 319 102-1) =====");
        System.out.println("Indication:    " + simple.getIndication(signatureId));
        System.out.println("SubIndication: " + simple.getSubIndication(signatureId));
        System.out.println("Assinado por:  " + simple.getSignedBy(signatureId));
        System.out.println("Instante:      " + simple.getSigningTime(signatureId));
        System.out.println("Formato:       " + simple.getSignatureFormat(signatureId));
        simple.getAdESValidationErrors(signatureId)
                .forEach(m -> System.out.println("Erro:          " + m.getValue()));
        simple.getAdESValidationWarnings(signatureId)
                .forEach(m -> System.out.println("Aviso:         " + m.getValue()));
        System.out.println("=============================================\n");

        assertEquals(Indication.TOTAL_PASSED, simple.getIndication(signatureId),
                () -> "Validação DSS não passou. SubIndication: " + simple.getSubIndication(signatureId)
                        + " — erros: " + simple.getAdESValidationErrors(signatureId));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

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

    /** Extrai os certificados do header protegido {@code x5c} do JWS produzido (folha → raiz). */
    private List<X509Certificate> extractX5c(String jws) throws Exception {
        JsonNode root = mapper.readTree(jws);
        String protectedB64 = root.get("signatures").get(0).get("protected").asText();
        JsonNode header = mapper.readTree(
                new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8));

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();
        for (JsonNode certNode : header.get("x5c")) {
            byte[] der = Base64.getDecoder().decode(certNode.asText());
            certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
        }
        assertFalse(certs.isEmpty(), "x5c vazio no JWS produzido");
        return certs;
    }
}
