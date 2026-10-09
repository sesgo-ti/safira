/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Aplicação de produção: API REST do Safira sobre o acervo ICP-Brasil da icpbrasil-truststore. */
@SpringBootApplication
public class SafiraApplication {

    public static void main(String[] args) {
        SpringApplication.run(SafiraApplication.class, args);
    }
}
