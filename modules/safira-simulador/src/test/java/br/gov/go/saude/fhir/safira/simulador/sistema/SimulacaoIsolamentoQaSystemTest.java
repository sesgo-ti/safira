/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SignAndValidateSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * QA adversarial do isolamento entre confiança simulada e real: assinatura simulada com a cadeia
 * inteira (inclusive a raiz simulada) no {@code x5c}, apresentada a um Safira em modo normal cuja
 * allowlist aponta para a AC simulada; e ativação parcial/indevida do modo simulação.
 */
@ActiveProfiles("simulador")
@SpringBootTest(properties = "safira.simulacao.enabled=false")
@Import(ModoIcpBrasilDeTeste.class)
class SimulacaoIsolamentoQaSystemTest {

    static SigningResult assinaturaComRaizNoX5c;

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        registry.add("safira.policy.accepted-certificate-policies[0].oid", SimulacaoPki.PKI::politicaOid);
        registry.add("safira.policy.accepted-certificate-policies[0].type", () -> "A3");
        registry.add("safira.policy.accepted-certificate-policies[0].issuer-sha256", SimulacaoPki.PKI::issuerSha256);
    }

    private static String[] ambiente() {
        return SimulacaoPki.ambiente().entrySet().stream()
                .map(entrada -> entrada.getKey() + "=" + entrada.getValue())
                .toArray(String[]::new);
    }

    /** Corpo de assinatura simulada com {@code certificateChain} = folha, AC e raiz simuladas. */
    private static String corpoComCadeiaCompleta() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(SimulacaoPki.PKI.signatario())) {
            keyStore.load(in, SimulacaoPki.PKI.senha().toCharArray());
        }
        Certificate[] cadeia = keyStore.getCertificateChain(GeradorPkiSimulada.ALIAS_SIGNATARIO);
        String folhaSo = "[\"" + Base64.getEncoder().encodeToString(cadeia[0].getEncoded()) + "\"]";
        String completa = Arrays.stream(cadeia).map(SimulacaoIsolamentoQaSystemTest::base64)
                .collect(Collectors.joining("\",\"", "[\"", "\"]"));
        return SimulacaoPki.signingBody(SimulacaoPki.PKI.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO,
                Instant.now().getEpochSecond()).replace("\"certificateChain\":" + folhaSo, "\"certificateChain\":" + completa);
    }

    private static String base64(Certificate certificado) {
        try {
            return Base64.getEncoder().encodeToString(certificado.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeAll
    static void assinarEmModoSimulacao() throws Exception {
        try (ConfigurableApplicationContext simulacao = new SpringApplicationBuilder(SimuladorTestApplication.class)
                .web(WebApplicationType.NONE)
                .profiles("simulador")
                .properties(ambiente())
                .run()) {
            PipelineResult<?> result = simulacao.getBean(SigningService.class).sign(corpoComCadeiaCompleta());
            assertThat(result).isInstanceOf(PipelineResult.Success.class);
            assinaturaComRaizNoX5c = (SigningResult) ((PipelineResult.Success<?>) result).getValue();
        }
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void shouldRejectSimulatedSignatureWhenX5cCarriesSimulatedRootAndModeIsOff() throws Exception {
        String body = SignAndValidateSystemTest.validationBody(assinaturaComRaizNoX5c.signatureJson(),
                JadesSigningSystemTest.example("bundle.json"), assinaturaComRaizNoX5c.provenanceJson());

        MvcResult result = mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(new ObjectMapper().readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("issue").get(0).get("details").get("coding").get(0).get("code").asText())
                .isEqualTo("CERT.NOT-ICP-BRASIL");
    }

    @Test
    void shouldFailStartupWhenSimulationHasNoAnchorsOutsideSimulatorApplication() {
        assertThatThrownBy(() -> new SpringApplicationBuilder(SimuladorTestApplication.class)
                .web(WebApplicationType.NONE)
                .profiles("simulador")
                .run().close())
                .hasStackTraceContaining("safira.simulacao.trust-anchors");
    }

    @Test
    void shouldFailStartupWhenSimulationAllowlistIssuerIsEmpty() {
        assertThatThrownBy(() -> new SpringApplicationBuilder(SimuladorTestApplication.class)
                .web(WebApplicationType.NONE)
                .profiles("simulador")
                .properties(ambiente())
                .run("--SAFIRA_SIMULACAO_ISSUER_SHA256=")
                .close())
                .hasStackTraceContaining("issuer-sha256");
    }

    @Test
    void shouldNotTrustSimulatedSignerWhenModeIsOverriddenOff() throws Exception {
        try (ConfigurableApplicationContext parcial = new SpringApplicationBuilder(SimuladorTestApplication.class,
                ModoIcpBrasilDeTeste.class)
                .web(WebApplicationType.NONE)
                .profiles("simulador")
                .properties(ambiente())
                .run("--safira.simulacao.enabled=false")) {
            PipelineResult<?> result = parcial.getBean(SigningService.class).sign(SimulacaoPki.signingBody(
                    SimulacaoPki.PKI.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond()));

            assertThat(result).isInstanceOf(PipelineResult.Failure.class);
        }
    }
}
