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
import br.gov.go.saude.fhir.safira.simulador.SimuladorApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.UseMainMethod;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Aplicação do simulador pelo {@code main}, por HTTP: PKI gerada na partida (testkit), revogação e
 * carimbo do tempo em memória, mesmo pipeline do {@code safira-rest} — sem rede e sem a lib.
 */
@SpringBootTest(classes = SimuladorApplication.class, webEnvironment = WebEnvironment.RANDOM_PORT,
        useMainMethod = UseMainMethod.ALWAYS)
class SimuladorApplicationSystemTest {

    static final Path DIRETORIO = diretorio();

    @LocalServerPort
    int porta;

    @Autowired
    PkiPersistida pki;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void diretorio(DynamicPropertyRegistry registry) {
        registry.add("safira.simulador.diretorio", DIRETORIO::toString);
    }

    private static Path diretorio() {
        try {
            return Files.createTempDirectory("safira-simulador-app");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private HttpResponse<String> enviar(String caminho, String corpo) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + porta + caminho))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(corpo, StandardCharsets.UTF_8))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private HttpResponse<String> assinar(Path p12, String alias, String estrategia) throws Exception {
        return enviar("/assinar", SimulacaoPki.signingBody(Files.readString(pki.senha()).strip(), p12, alias,
                Instant.now().getEpochSecond(), estrategia));
    }

    private HttpResponse<String> validar(JsonNode assinada) throws Exception {
        return validar(assinada, Instant.now().getEpochSecond());
    }

    private HttpResponse<String> validar(JsonNode assinada, long referenceTimestamp) throws Exception {
        return enviar("/validar", SignAndValidateSystemTest.validationBody(assinada.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), assinada.get("provenance").toString(), referenceTimestamp));
    }

    private static String code(JsonNode outcome) {
        return outcome.get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    @Test
    void shouldReportReadinessUpWhenPkiIsGeneratedAtStartup() throws Exception {
        HttpResponse<String> resposta = http.send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + porta + "/actuator/health/readiness")).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        assertThat(resposta.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(resposta.body()).get("status").asText()).isEqualTo("UP");
    }

    @Test
    void shouldExposeOnlyPublicMaterialAtPkiEndpoint() throws Exception {
        HttpResponse<String> resposta = http.send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + porta + "/simulacao/pki")).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        JsonNode corpo = mapper.readTree(resposta.body());

        assertThat(resposta.statusCode()).isEqualTo(200);
        assertThat(corpo.fieldNames()).toIterable().containsExactlyInAnyOrder(
                "diretorio", "raiz", "ac", "cadeiaSignatario", "issuerSha256", "politicaOid");
        assertThat(corpo.get("diretorio").asText()).isEqualTo(pki.diretorio().toString());
        assertThat(corpo.get("raiz").asText()).isEqualTo(Files.readString(pki.raiz()));
        assertThat(corpo.get("ac").asText()).isEqualTo(Files.readString(pki.ac()));
        assertThat(corpo.get("cadeiaSignatario")).hasSize(3);
        assertThat(corpo.get("cadeiaSignatario").get(2).asText()).isEqualTo(Files.readString(pki.raiz()));
        assertThat(corpo.get("issuerSha256").asText()).isEqualTo(pki.issuerSha256());
        assertThat(resposta.body()).doesNotContain(Files.readString(pki.senha()).strip())
                .doesNotContain("PRIVATE")
                .doesNotContain(linhaDoMeio(Files.readAllBytes(pki.signatario())));
        for (KeyPair chaves : List.of(pki.pki().chavesRaiz(), pki.pki().chavesAc(), pki.pki().chavesTsa(),
                pki.pki().chavesSignatario(), pki.pki().chavesRevogado())) {
            assertThat(resposta.body()).doesNotContain(linhaDoMeio(chaves.getPrivate().getEncoded()));
        }
    }

    /** Terceira linha (64 caracteres) do Base64 do DER: aparece igual em PEM ou em Base64 corrido. */
    private static String linhaDoMeio(byte[] der) {
        return Base64.getEncoder().encodeToString(der).substring(128, 192);
    }

    @Test
    void shouldWriteGeneratedPkiToConfiguredDirectory() {
        assertThat(pki.signatario()).isEqualTo(DIRETORIO.resolve("signatario.p12").toAbsolutePath().normalize());
        assertThat(pki.signatario()).isRegularFile();
        assertThat(pki.raiz()).isRegularFile();
    }

    @Test
    void shouldSignWithGeneratedP12AndValidateWithSimulationNotice() throws Exception {
        HttpResponse<String> assinada = assinar(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO, "iat");
        assertThat(assinada.statusCode()).isEqualTo(200);

        HttpResponse<String> validada = validar(mapper.readTree(assinada.body()));

        assertThat(validada.statusCode()).isEqualTo(200);
        assertThat(code(mapper.readTree(validada.body()))).isEqualTo("VALIDATION.SUCCESS");
        assertThat(validada.body()).contains(AvisoSimulacaoAdvice.TEXTO);
    }

    @Test
    void shouldRejectSigningWhenGeneratedSignerIsRevoked() throws Exception {
        HttpResponse<String> resposta = assinar(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO, "iat");

        assertThat(resposta.statusCode()).isEqualTo(422);
        assertThat(code(mapper.readTree(resposta.body()))).isEqualTo("CERT.REVOKED");
    }

    @Test
    void shouldSignBaselineTWithInMemoryTsaAndValidate() throws Exception {
        HttpResponse<String> assinada = assinar(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO, "tsa");
        assertThat(assinada.statusCode()).isEqualTo(200);

        // referência após o carimbo (genTime com milissegundos), como nos testes de B-T do safira-rest
        HttpResponse<String> validada = validar(mapper.readTree(assinada.body()), Instant.now().getEpochSecond() + 2);

        assertThat(validada.statusCode()).isEqualTo(200);
        assertThat(code(mapper.readTree(validada.body()))).isEqualTo("VALIDATION.SUCCESS");
        assertThat(validada.body()).contains(AvisoSimulacaoAdvice.TEXTO);
    }
}
