/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** PKI de simulação gerada uma vez por JVM e as variáveis {@code SAFIRA_SIMULACAO_*} que a apontam. */
final class SimulacaoPki {

    static final Resultado PKI = gerar();

    private SimulacaoPki() {
    }

    private static Resultado gerar() {
        try {
            return GeradorPkiSimulada.gerar(Files.createTempDirectory("safira-simulacao-pki"), Opcoes.padrao());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Variáveis lidas pelo perfil {@code simulacao} (application-simulacao.yml). */
    static Map<String, String> ambiente() {
        Map<String, String> ambiente = new LinkedHashMap<>();
        ambiente.put("SAFIRA_SIMULACAO_TRUST_ANCHORS", PKI.raiz().toUri().toString());
        ambiente.put("SAFIRA_SIMULACAO_INTERMEDIATES", PKI.ac().toUri().toString());
        ambiente.put("SAFIRA_SIMULACAO_CRLS", PKI.lcrRaiz().toUri() + "," + PKI.lcrAc().toUri());
        ambiente.put("SAFIRA_SIMULACAO_ISSUER_SHA256", PKI.issuerSha256());
        ambiente.put("SAFIRA_TRUSTSTORE_DIR", "target/icpbrasil-truststore-simulacao");
        return ambiente;
    }

    /** Corpo de {@code POST /assinar} com o PKCS#12 simulado e estratégia {@code iat}. */
    static String signingBody(Path p12, String alias, long referenceTimestamp) throws Exception {
        byte[] conteudo = Files.readAllBytes(p12);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            keyStore.load(in, PKI.senha().toCharArray());
        }
        String folha = Base64.getEncoder().encodeToString(keyStore.getCertificate(alias).getEncoded());
        return "{\"bundle\":" + JadesSigningSystemTest.example("bundle.json")
                + ",\"provenance\":" + JadesSigningSystemTest.example("provenance.json")
                + ",\"signerCryptoMaterial\":{\"type\":\"PKCS12\",\"contentBase64\":\""
                + Base64.getEncoder().encodeToString(conteudo) + "\",\"password\":\"" + PKI.senha()
                + "\",\"alias\":\"" + alias + "\"}"
                + ",\"certificateChain\":[\"" + folha + "\"]"
                + ",\"referenceTimestamp\":" + referenceTimestamp
                + ",\"strategy\":\"iat\""
                + ",\"policyIdentifierUri\":\"" + JadesSigningSystemTest.POLICY_URI + "\"}";
    }
}
