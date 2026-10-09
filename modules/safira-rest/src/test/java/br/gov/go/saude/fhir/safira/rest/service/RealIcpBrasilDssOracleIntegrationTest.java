/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.Reports;
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
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Oráculo de interoperabilidade com certificado ICP-Brasil real (PKCS#12): produz um JAdES-B-B
 * no formato da política 0.2.0 diretamente pelo {@link JadesSigningService} — fora da pipeline,
 * que recusaria o A1 (C16) — e o valida com o verificador de produção do EU DSS: acervo real do
 * ITI e revogação OCSP/CRL obtida pelo próprio DSS.
 *
 * <p>Ignorado sem {@code -Dpfx.path} e {@code -Dpfx.password}; requer acesso à rede (ITI,
 * OCSP/CRL). Execução:
 * <pre>
 * ./mvnw -Pintegration-tests test -pl modules/safira-rest -am \
 *     -Dtest=RealIcpBrasilDssOracleIntegrationTest -Dsurefire.failIfNoSpecifiedTests=false \
 *     -Dpfx.path=/caminho/cert.pfx -Dpfx.password=senha
 * </pre>
 */
@Tag("integration")
@EnabledIfSystemProperty(named = "pfx.path", matches = ".+")
@SpringBootTest(properties = {
        "icpbrasil-truststore.bootstrap.enabled=true",
        "icpbrasil-truststore.scheduling.enabled=false",
        "icpbrasil-truststore.filesystem.base-dir=target/icpbrasil-truststore-it"
})
class RealIcpBrasilDssOracleIntegrationTest {

    @Autowired
    VerificadoresDss certificateVerifiers;

    @Test
    void shouldValidateRealChainWithDssUsingOnlineRevocation() throws Exception {
        String pfxPath = System.getProperty("pfx.path");
        String pfxPassword = System.getProperty("pfx.password");
        Assumptions.assumeTrue(pfxPath != null && pfxPassword != null,
                "Teste ignorado: defina -Dpfx.path e -Dpfx.password para executar com certificado real");

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(Files.readAllBytes(Path.of(pfxPath))), pfxPassword.toCharArray());
        String alias = firstKeyAlias(keyStore);
        PrivateKey key = (PrivateKey) keyStore.getKey(alias, pfxPassword.toCharArray());
        List<X509Certificate> supplied = Arrays.stream(keyStore.getCertificateChain(alias))
                .map(X509Certificate.class::cast).toList();

        // Cadeia validada pelo DSS (acervo real, revogação online) — mesma rotina do pkix-chain-validation
        CertificateReports certificateReports = new CertificateValidationService().validate(supplied.getFirst(),
                supplied.subList(1, supplied.size()), certificateVerifiers.paraOperacao(List.of()).orElseThrow());
        String leafId = new CertificateToken(supplied.getFirst()).getDSSIdAsString();
        assertThat(certificateReports.getSimpleReport().getCertificateIndication(leafId)).isEqualTo(Indication.PASSED);
        List<X509Certificate> chain = new ArrayList<>(List.of(supplied.getFirst()));
        certificateReports.getDiagnosticData().getUsedCertificateById(leafId).getCertificateChain().stream()
                .filter(certificate -> !certificate.getId().equals(leafId))
                .forEach(certificate -> chain.add(DSSUtils.loadCertificate(certificate.getBinaries()).getCertificate()));

        JadesSigningService signing = new JadesSigningService();
        byte[] payload = MessageDigest.getInstance("SHA-256").digest("oraculo".getBytes(StandardCharsets.UTF_8));
        JadesSigningSession session = signing.newSession(new JadesSigningService.Request(
                chain, payload, Instant.now().getEpochSecond(), Policy020.POLICY_URI));
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(key);
        rsa.update(signing.dataToSign(session));
        String jws = signing.sign(session, rsa.sign());

        // Verificador de produção: acervo real como âncoras/adjuntas e OCSP/CRL/AIA online pelo DSS
        Reports reports = new JadesValidationService().validate(jws,
                certificateVerifiers.paraOperacao(List.of()).orElseThrow());
        String id = reports.getSimpleReport().getFirstSignatureId();

        assertThat(reports.getSimpleReport().getIndication(id)).isEqualTo(Indication.TOTAL_PASSED);
        assertThat(reports.getSimpleReport().getSignatureFormat(id)).isEqualTo(SignatureLevel.JAdES_BASELINE_B);
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
