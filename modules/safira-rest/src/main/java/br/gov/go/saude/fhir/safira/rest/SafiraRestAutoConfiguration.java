/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest;

import br.gov.go.saude.fhir.safira.rest.api.SignatureController;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.rest.service.ValidationService;
import br.gov.go.saude.fhir.safira.rest.service.VersionsService;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * Registra a API REST do Safira (controller e serviços) na aplicação que inclui esta biblioteca.
 * A fonte de confiança e o filtro de destino de rede vêm da aplicação.
 */
@AutoConfiguration(after = SafiraStepsAutoConfiguration.class)
@Import({SignatureController.class, SigningService.class, ValidationService.class, VersionsService.class})
public class SafiraRestAutoConfiguration {
}
