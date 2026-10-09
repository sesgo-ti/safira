/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.CodigosDeSaida.Operacao;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.Callable;

/**
 * {@code safira validar}: compõe o corpo de {@code POST /validar} (instante atual como referência) e
 * chama o {@code ValidationService} — mesmo parser e mesmo pipeline da API. Sai com 0 só com
 * {@code VALIDATION.SUCCESS} ({@link CodigosDeSaida#de}).
 */
@Command(name = "validar", description = "Valida a assinatura JAdES (política 0.2.0) de um Bundle FHIR.",
        sortOptions = false)
final class Validar implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = "--signature", required = true, paramLabel = "ARQUIVO", description = "Signature FHIR (JSON).")
    Path signature;

    @Option(names = "--bundle", required = true, paramLabel = "ARQUIVO", description = "Bundle FHIR assinado (JSON).")
    Path bundle;

    @Option(names = "--provenance", required = true, paramLabel = "ARQUIVO",
            description = "Provenance FHIR final, com a assinatura (JSON).")
    Path provenance;

    @Option(names = "--politica", paramLabel = "URI", defaultValue = Policy020.POLICY_URI,
            description = "URI da política de assinatura (padrão: ${DEFAULT-VALUE}).")
    String politica;

    @Mixin
    OpcoesComuns opcoes;

    @Override
    public Integer call() {
        return Execucao.executar(spec, opcoes, this::validar);
    }

    private Execucao.Resultado validar(ContextoSafira contexto) {
        Entradas entradas = new Entradas(contexto.operacional());
        String signatureJson = entradas.objeto(signature);
        String bundleJson = entradas.bundle(bundle);
        String provenanceJson = entradas.objeto(provenance);

        StringBuilder corpo = new StringBuilder("{\"signature\":").append(signatureJson)
                .append(",\"bundle\":").append(bundleJson)
                .append(",\"provenance\":").append(provenanceJson)
                .append(",\"referenceTimestamp\":").append(Instant.now().getEpochSecond())
                .append(",\"policyIdentifierUri\":");
        LosslessJson.appendEscaped(corpo, politica);
        corpo.append('}');

        PipelineResult<OperationOutcome> resultado = contexto.validacao().validate(corpo.toString());
        OperationOutcome outcome = resultado.isSuccess() ? resultado.getValue() : resultado.getExceptionDetails();
        int saida = CodigosDeSaida.de(outcome, Operacao.VALIDACAO);
        if (saida == CodigosDeSaida.SUCESSO && opcoes.modo.simulacao()) {
            outcome = AvisoSimulacaoAdvice.marcar(outcome);
        }
        return new Execucao.Resultado(contexto.json(outcome), saida);
    }
}
