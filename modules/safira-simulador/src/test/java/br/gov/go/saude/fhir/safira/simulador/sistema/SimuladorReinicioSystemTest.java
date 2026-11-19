/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SignAndValidateSystemTest;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida.Situacao;
import br.gov.go.saude.fhir.safira.simulador.SimuladorApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Reinício do simulador (Review Focus 4): a PKI gerada na primeira partida é persistida e
 * reaproveitada — assinaturas anteriores continuam válidas, o revogado continua revogado e o
 * carimbo do tempo segue disponível; diretório corrompido impede a partida.
 */
@ExtendWith(OutputCaptureExtension.class)
class SimuladorReinicioSystemTest {

    @TempDir
    Path diretorio;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    private ConfigurableApplicationContext iniciar() {
        return SimuladorApplication.aplicacao().run("--server.port=0", "--safira.simulador.diretorio=" + diretorio);
    }

    private HttpResponse<String> enviar(ConfigurableApplicationContext contexto, String caminho, String corpo)
            throws Exception {
        String porta = contexto.getEnvironment().getProperty("local.server.port");
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + porta + caminho))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(corpo, StandardCharsets.UTF_8))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private HttpResponse<String> assinar(ConfigurableApplicationContext contexto, String p12, String alias,
                                         String estrategia) throws Exception {
        String senha = Files.readString(diretorio.resolve("senha.txt")).strip();
        return enviar(contexto, "/assinar", SimulacaoPki.signingBody(senha, diretorio.resolve(p12), alias,
                Instant.now().getEpochSecond(), estrategia));
    }

    private HttpResponse<String> validar(ConfigurableApplicationContext contexto, JsonNode assinada,
                                         long referenceTimestamp) throws Exception {
        return enviar(contexto, "/validar", SignAndValidateSystemTest.validationBody(
                assinada.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                assinada.get("provenance").toString(), referenceTimestamp));
    }

    private String code(HttpResponse<String> resposta) throws Exception {
        return mapper.readTree(resposta.body()).get("issue").get(0).get("details").get("coding").get(0)
                .get("code").asText();
    }

    @Test
    void shouldReuseExistingPkiOnRestart() throws Exception {
        HttpResponse<String> assinada;
        try (ConfigurableApplicationContext primeira = iniciar()) {
            assertThat(primeira.getBean(PkiPersistida.class).situacao()).isEqualTo(Situacao.GERADA);
            assinada = assinar(primeira, "signatario.p12", GeradorPkiSimulada.ALIAS_SIGNATARIO, "iat");
        }
        assertThat(assinada.statusCode()).isEqualTo(200);

        try (ConfigurableApplicationContext segunda = iniciar()) {
            HttpResponse<String> validada = validar(segunda, mapper.readTree(assinada.body()),
                    Instant.now().getEpochSecond());

            assertThat(segunda.getBean(PkiPersistida.class).situacao()).isEqualTo(Situacao.REUTILIZADA);
            assertThat(validada.statusCode()).isEqualTo(200);
            assertThat(code(validada)).isEqualTo("VALIDATION.SUCCESS");
            assertThat(validada.body()).contains(AvisoSimulacaoAdvice.TEXTO);
        }
    }

    @Test
    void shouldKeepRevokedSignerRevokedAfterRestart() throws Exception {
        iniciar().close();

        try (ConfigurableApplicationContext contexto = iniciar()) {
            HttpResponse<String> resposta = assinar(contexto, "revogado.p12", GeradorPkiSimulada.ALIAS_REVOGADO, "iat");

            assertThat(resposta.statusCode()).isEqualTo(422);
            assertThat(code(resposta)).isEqualTo("CERT.REVOKED");
        }
    }

    @Test
    void shouldSignBaselineTWithPersistedTsaAfterRestart() throws Exception {
        iniciar().close();

        try (ConfigurableApplicationContext contexto = iniciar()) {
            HttpResponse<String> assinada = assinar(contexto, "signatario.p12", GeradorPkiSimulada.ALIAS_SIGNATARIO, "tsa");
            assertThat(assinada.statusCode()).isEqualTo(200);

            // referência após o carimbo (genTime com milissegundos), como nos testes de B-T do safira-rest
            HttpResponse<String> validada = validar(contexto, mapper.readTree(assinada.body()),
                    Instant.now().getEpochSecond() + 2);

            assertThat(code(validada)).isEqualTo("VALIDATION.SUCCESS");
        }
    }

    @Test
    void shouldFailStartupWhenPkiDirectoryIsCorrupted() throws Exception {
        iniciar().close();
        Files.writeString(diretorio.resolve("autoridades.p12"), "lixo");

        assertThatThrownBy(this::iniciar)
                .hasStackTraceContaining("corrompida")
                .hasStackTraceContaining("autoridades.p12");
    }

    @Test
    void shouldLogPathsButNeverThePassword(CapturedOutput saida) throws Exception {
        iniciar().close();
        String senha = Files.readString(diretorio.resolve("senha.txt")).strip();

        assertThat(saida.getOut()).contains(diretorio.resolve("senha.txt").toString())
                .contains(diretorio.resolve("signatario.p12").toString())
                .doesNotContain(senha);
    }
}
