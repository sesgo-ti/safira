/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Steps obrigatórios, na ordem relativa exigida, de um pipeline (política + operação). Conferidos
 * na partida ({@link #verificar}): um pipeline configurado sem algum deles, ou com eles fora de
 * ordem, impede a aplicação de subir. Steps extras entre os obrigatórios são permitidos.
 */
public record RequiredSteps(PipelineKey pipelineKey, List<String> stepIds) {

    public RequiredSteps {
        Objects.requireNonNull(pipelineKey, "pipelineKey");
        stepIds = List.copyOf(stepIds);
    }

    /**
     * @throws IllegalStateException se algum pipeline configurado não contém os steps obrigatórios
     *                               da sua chave na ordem exigida
     */
    public static void verificar(Collection<PipelineDefinition> definitions, Collection<RequiredSteps> required) {
        for (RequiredSteps requirement : required) {
            for (PipelineDefinition definition : definitions) {
                if (definition.pipelineKey().equals(requirement.pipelineKey())) {
                    requirement.conferir(definition.stepIds());
                }
            }
        }
    }

    private void conferir(List<String> configured) {
        List<String> ausentes = stepIds.stream().filter(id -> !configured.contains(id)).toList();
        if (!ausentes.isEmpty()) {
            throw new IllegalStateException("Pipeline " + descricao() + " sem os steps obrigatórios " + ausentes
                    + "; obrigatórios, nesta ordem: " + stepIds);
        }
        int anterior = -1;
        for (String id : stepIds) {
            int posicao = configured.indexOf(id);
            if (posicao < anterior) {
                throw new IllegalStateException("Pipeline " + descricao() + " com os steps obrigatórios fora de ordem: "
                        + configured + "; obrigatórios, nesta ordem: " + stepIds);
            }
            anterior = posicao;
        }
    }

    private String descricao() {
        return "[" + pipelineKey.politicsVersion() + " | " + pipelineKey.operation() + "]";
    }
}
