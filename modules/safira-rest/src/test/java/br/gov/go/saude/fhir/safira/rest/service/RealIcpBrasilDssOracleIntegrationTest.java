/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.revocation.LibRevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
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
import java.security.cert.TrustAnchor;
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
 * que recusaria o A1 (C16) — e o valida com o EU DSS usando âncoras do acervo real do ITI e
 * evidências de revogação reais obtidas pela lib icpbrasil-truststore.
 *
 * <p>Ignorado sem {@code -Dpfx.path} e {@code -Dpfx.password}; requer acesso à rede (ITI, AIA,
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
    PkixCertificateValidator pkixCertificateValidator;

    @Autowired
    RevocationService revocationService;

    @Autowired
    TrustMaterialSource trustMaterialSource;

    @Test
    void shouldValidateRealChainWithDssUsingLibEvidence() throws Exception {
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

        // PKIX real (AIA, âncora do acervo, revogação) fornece a cadeia completa até a raiz
        ValidationResult pkix = pkixCertificateValidator.validate(supplied.getFirst(), supplied.subList(1, supplied.size()));
        assertThat(pkix).isInstanceOf(ValidationResult.Valid.class);
        ValidationResult.Valid valid = (ValidationResult.Valid) pkix;
        List<X509Certificate> chain = new ArrayList<>(valid.path());
        chain.add(valid.anchor());

        JadesSigningService signing = new JadesSigningService();
        byte[] payload = MessageDigest.getInstance("SHA-256").digest("oraculo".getBytes(StandardCharsets.UTF_8));
        JadesSigningSession session = signing.newSession(new JadesSigningService.Request(
                chain, payload, Instant.now().getEpochSecond(), Policy020.POLICY_URI));
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(key);
        rsa.update(signing.dataToSign(session));
        String jws = signing.sign(session, rsa.sign());

        LibRevocationEvidence.Outcome outcome = LibRevocationEvidence.collect(revocationService, List.of(chain));
        assertThat(outcome).isInstanceOf(LibRevocationEvidence.Outcome.Ok.class);
        LibRevocationEvidence.Collected evidence = ((LibRevocationEvidence.Outcome.Ok) outcome).collected();
        List<X509Certificate> anchors = trustMaterialSource.current().orElseThrow().anchors().stream()
                .map(TrustAnchor::getTrustedCert).toList();

        Reports reports = new JadesValidationService().validate(jws, CertificateVerifiers.create(anchors,
                EvidenceRevocationSources.ocspFromEvidence(evidence.ocspResponses()),
                EvidenceRevocationSources.crlFromEvidence(evidence.crls())));
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
