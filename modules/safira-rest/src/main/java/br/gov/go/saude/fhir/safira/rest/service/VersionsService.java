/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.PipelineConfig;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class VersionsService {

    public final PipelineConfig pipelineConfig;

    public VersionsService(PipelineConfig pipelineConfig) {
        this.pipelineConfig = pipelineConfig;
    }

    public Set<String> getVersionsSupported() {
        return pipelineConfig.pipelines().stream()
                .map(pipeline -> pipeline.pipelineKey().politicsVersion())
                .collect(Collectors.toUnmodifiableSet());
    }
}
