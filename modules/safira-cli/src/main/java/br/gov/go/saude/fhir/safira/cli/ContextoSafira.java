/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.rest.service.ValidationService;
import br.gov.go.saude.fhir.safira.simulador.PkiGeradaNaPartida;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Contexto Spring de uma execução da CLI, no modo escolhido, com os serviços do {@code safira-rest}.
 *
 * <p>O modo é imposto por argumentos do Spring (precedência máxima, acima de variáveis de ambiente e
 * propriedades de sistema): {@code safira.simulacao.enabled} e a exclusão das auto-configurações do outro
 * modo. A configuração vem de {@code safira-cli.yml} e {@code safira-cli-<modo>.yml} (nunca dos
 * {@code application*.yml} do app ou do simulador), mais {@code --config}. Depois da partida, exige
 * exatamente uma {@link FonteDeConfianca}, do tipo do modo.
 */
public final class ContextoSafira implements AutoCloseable {

    static final String NOME_DA_CONFIGURACAO = "safira-cli";

    /** Stack trace no log (stderr) só com {@code --verbose}: {@code %nopex} omite a exceção, {@code %ex} a mostra. */
    static final String CONVERSAO_DE_EXCECAO = "LOG_EXCEPTION_CONVERSION_WORD";

    private final ConfigurableApplicationContext aplicacao;

    private ContextoSafira(ConfigurableApplicationContext aplicacao) {
        this.aplicacao = aplicacao;
    }

    /**
     * @param pkiDir  diretório da PKI simulada (só no modo simulação; nulo = padrão)
     * @param config  YAML adicional (nulo = nenhum)
     * @param verbose mostra o log do Spring (inclusive da falha da partida) e os avisos do EU DSS (stderr)
     */
    public static ContextoSafira iniciar(Modo modo, Path pkiDir, Path config, boolean verbose) {
        return iniciar(modo, pkiDir, config, null, verbose);
    }

    /** @param timeoutAcervo timeout do download do acervo ICP-Brasil em segundos (só icpbrasil; nulo = padrão da CLI) */
    public static ContextoSafira iniciar(Modo modo, Path pkiDir, Path config, Integer timeoutAcervo, boolean verbose) {
        if (pkiDir != null && !modo.simulacao()) {
            throw new FalhaDeUso("--pki-dir só vale com --modo simulacao: os modos não se misturam.");
        }
        if (timeoutAcervo != null && modo != Modo.ICPBRASIL) {
            throw new FalhaDeUso("--timeout-acervo só vale com --modo icpbrasil: os modos não se misturam.");
        }
        if (config != null && !Files.isRegularFile(config)) {
            throw new FalhaDeUso("Arquivo de configuração não encontrado: " + config);
        }
        // lida pelo logback.xml; propriedade de sistema porque o Spring Boot não sobrescreve a de uma partida anterior
        System.setProperty(CONVERSAO_DE_EXCECAO, verbose ? "%ex" : "%nopex");
        SpringApplication aplicacao = new SpringApplication(SafiraCliAplicacao.class);
        aplicacao.setWebApplicationType(WebApplicationType.NONE);
        aplicacao.setBannerMode(Banner.Mode.OFF);
        aplicacao.setLogStartupInfo(false);
        aplicacao.setRegisterShutdownHook(false);
        aplicacao.setAdditionalProfiles(modo.nome());
        if (modo.simulacao()) {
            aplicacao.addInitializers(new PkiGeradaNaPartida());
        }
        ConfigurableApplicationContext contexto = aplicacao.run(argumentos(modo, pkiDir, config, timeoutAcervo, verbose));
        try {
            exigirFonteUnica(contexto, modo);
        } catch (RuntimeException e) {
            contexto.close();
            throw e;
        }
        return new ContextoSafira(contexto);
    }

    private static String[] argumentos(Modo modo, Path pkiDir, Path config, Integer timeoutAcervo, boolean verbose) {
        List<String> argumentos = new ArrayList<>(List.of(
                "--spring.config.name=" + NOME_DA_CONFIGURACAO,
                "--safira.simulacao.enabled=" + modo.simulacao(),
                "--spring.autoconfigure.exclude=" + String.join(",", modo.excluidas()),
                "--logging.level.org.springframework=" + (verbose ? "WARN" : "OFF")));
        if (verbose) {
            argumentos.add("--logging.level.eu.europa.esig=WARN");
        }
        if (timeoutAcervo != null) {
            argumentos.add("--icpbrasil-truststore.network.download-timeout-seconds=" + timeoutAcervo);
        }
        if (config != null) {
            argumentos.add("--spring.config.additional-location=file:" + config.toAbsolutePath());
        }
        if (pkiDir != null) {
            argumentos.add("--safira.simulador.diretorio=" + pkiDir.toAbsolutePath());
        }
        return argumentos.toArray(String[]::new);
    }

    static void exigirFonteUnica(ConfigurableApplicationContext contexto, Modo modo) {
        Map<String, FonteDeConfianca> fontes = contexto.getBeansOfType(FonteDeConfianca.class);
        if (fontes.size() != 1 || !modo.fonte().isInstance(fontes.values().iterator().next())) {
            throw new IllegalStateException("O modo " + modo.nome() + " exige uma única fonte de confiança "
                    + modo.fonte().getSimpleName() + "; encontradas: " + fontes.values().stream()
                    .map(fonte -> fonte.getClass().getSimpleName()).toList());
        }
    }

    ConfigurableApplicationContext aplicacao() {
        return aplicacao;
    }

    SigningService assinatura() {
        return aplicacao.getBean(SigningService.class);
    }

    ValidationService validacao() {
        return aplicacao.getBean(ValidationService.class);
    }

    SafiraOperationalConfigProperties operacional() {
        return aplicacao.getBean(SafiraOperationalConfigProperties.class);
    }

    /** PKI simulada persistida aberta na partida (só no modo simulação). */
    Optional<PkiPersistida> pkiSimulada() {
        return aplicacao.getBeanProvider(PkiPersistida.class).stream().findFirst();
    }

    /** Serializa como a API REST (mesmo {@code JsonMapper} do contexto). */
    String json(Object valor) {
        JsonMapper mapper = aplicacao.getBeanProvider(JsonMapper.class).getIfAvailable(() -> JsonMapper.builder().build());
        return mapper.writeValueAsString(valor);
    }

    @Override
    public void close() {
        aplicacao.close();
    }
}
