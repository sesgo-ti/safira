/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.CodigosDeSaida.Operacao;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * {@code safira assinar}: compõe o corpo de {@code POST /assinar} (PKCS#12, cadeia do PKCS#12, instante
 * atual) e chama o {@code SigningService} — mesmo parser e mesmo pipeline da API.
 */
@Command(name = "assinar", description = "Cria a assinatura JAdES (política 0.2.0) de um Bundle FHIR.",
        sortOptions = false)
final class Assinar implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = "--bundle", required = true, paramLabel = "ARQUIVO", description = "Bundle FHIR (JSON).")
    Path bundle;

    @Option(names = "--provenance", required = true, paramLabel = "ARQUIVO", description = "Provenance FHIR (JSON).")
    Path provenance;

    @Option(names = "--p12", required = true, paramLabel = "ARQUIVO", description = "PKCS#12 do signatário.")
    Path p12;

    @ArgGroup(exclusive = true, multiplicity = "1")
    FonteDaSenha senha;

    @Option(names = "--alias", description = "Alias da chave no PKCS#12 (dispensável com uma só chave).")
    String alias;

    @Option(names = "--estrategia", required = true, paramLabel = "iat|tsa",
            description = "Resultado pretendido: iat (JAdES-B-B) ou tsa (JAdES-B-T).")
    String estrategia;

    @Option(names = "--politica", paramLabel = "URI", defaultValue = Policy020.POLICY_URI,
            description = "URI da política de assinatura (padrão: ${DEFAULT-VALUE}).")
    String politica;

    @Mixin
    OpcoesComuns opcoes;

    @Override
    public Integer call() {
        return Execucao.executar(spec, opcoes, this::assinar, bundle, provenance, p12, senha.arquivo);
    }

    private Execucao.Resultado assinar(ContextoSafira contexto) {
        Entradas entradas = new Entradas(contexto.operacional());
        String bundleJson = entradas.bundle(bundle);
        String provenanceJson = entradas.objeto(provenance);
        byte[] conteudo = entradas.binario(p12);
        String senhaDoP12 = senha.ler(spec.commandLine().getErr());
        KeyStore chaves = abrir(conteudo, senhaDoP12);
        String aliasDaChave = aliasDaChave(chaves);

        StringBuilder corpo = new StringBuilder("{\"bundle\":").append(bundleJson)
                .append(",\"provenance\":").append(provenanceJson)
                .append(",\"signerCryptoMaterial\":{\"type\":\"PKCS12\",\"contentBase64\":");
        LosslessJson.appendEscaped(corpo, Base64.getEncoder().encodeToString(conteudo));
        corpo.append(",\"password\":");
        LosslessJson.appendEscaped(corpo, senhaDoP12);
        corpo.append(",\"alias\":");
        LosslessJson.appendEscaped(corpo, aliasDaChave);
        corpo.append("},\"certificateChain\":[");
        List<String> cadeia = cadeia(chaves, aliasDaChave);
        for (int i = 0; i < cadeia.size(); i++) {
            if (i > 0) {
                corpo.append(',');
            }
            LosslessJson.appendEscaped(corpo, cadeia.get(i));
        }
        corpo.append("],\"referenceTimestamp\":").append(Instant.now().getEpochSecond()).append(",\"strategy\":");
        LosslessJson.appendEscaped(corpo, estrategia);
        corpo.append(",\"policyIdentifierUri\":");
        LosslessJson.appendEscaped(corpo, politica);
        corpo.append('}');

        PipelineResult<?> resultado = contexto.assinatura().sign(corpo.toString());
        return switch (resultado) {
            // mesmo envelope da API (DIVERGENCIA-IG D12); na simulação, marcado
            case PipelineResult.Success<?> sucesso when sucesso.getValue() instanceof SigningResult assinada ->
                    new Execucao.Resultado("{\"signature\":" + assinada.signatureJson()
                            + ",\"provenance\":" + assinada.provenanceJson()
                            + (opcoes.modo.simulacao() ? ",\"simulacao\":\"" + AvisoSimulacaoAdvice.TEXTO + "\"" : "")
                            + "}", CodigosDeSaida.SUCESSO);
            // sem Signature/Provenance não há evidência de sucesso
            case PipelineResult.Success<?> sucesso ->
                    new Execucao.Resultado(contexto.json(sucesso.getValue()), CodigosDeSaida.INCONCLUSIVO);
            case PipelineResult.Failure<?> falha -> new Execucao.Resultado(contexto.json(falha.getExceptionDetails()),
                    CodigosDeSaida.de(falha.getExceptionDetails(), Operacao.ASSINATURA));
        };
    }

    private static KeyStore abrir(byte[] conteudo, String senhaDoP12) {
        try {
            KeyStore chaves = KeyStore.getInstance("PKCS12");
            chaves.load(new ByteArrayInputStream(conteudo), senhaDoP12.toCharArray());
            return chaves;
        } catch (IOException | GeneralSecurityException e) {
            throw new FalhaDeUso("Não foi possível abrir o PKCS#12 com a senha informada.",
                    Entradas.outcome(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE, "security",
                            "PKCS#12 ilegível ou senha incorreta."));
        }
    }

    private String aliasDaChave(KeyStore chaves) {
        try {
            if (alias != null) {
                if (!chaves.isKeyEntry(alias)) {
                    throw new FalhaDeUso("O PKCS#12 não tem chave privada com o alias '" + alias + "'.");
                }
                return alias;
            }
            List<String> comChave = Collections.list(chaves.aliases()).stream()
                    .filter(candidato -> eChave(chaves, candidato)).toList();
            if (comChave.size() != 1) {
                throw new FalhaDeUso("O PKCS#12 tem " + comChave.size() + " chaves privadas: informe --alias.");
            }
            return comChave.getFirst();
        } catch (GeneralSecurityException e) {
            throw new FalhaDeUso("Não foi possível listar as chaves do PKCS#12.");
        }
    }

    private static boolean eChave(KeyStore chaves, String alias) {
        try {
            return chaves.isKeyEntry(alias);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static List<String> cadeia(KeyStore chaves, String alias) {
        try {
            Certificate[] certificados = chaves.getCertificateChain(alias);
            if (certificados == null) {
                return List.of();
            }
            Base64.Encoder base64 = Base64.getEncoder();
            List<String> codificados = new ArrayList<>();
            for (Certificate certificado : certificados) {
                codificados.add(base64.encodeToString(certificado.getEncoded()));
            }
            return codificados;
        } catch (GeneralSecurityException e) {
            throw new FalhaDeUso("Não foi possível ler a cadeia de certificados do PKCS#12.");
        }
    }
}
