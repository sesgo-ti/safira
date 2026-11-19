/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Fronteiras do simulador: o núcleo não o conhece, e ele só troca a fonte de confiança — não usa a
 * icpbrasil-truststore nem o app de produção. Importa somente classes de produção.
 */
@AnalyzeClasses(packages = "br.gov.go.saude", importOptions = ImportOption.DoNotIncludeTests.class)
class ArquiteturaSimuladorTest {

    @ArchTest
    static final ArchRule nucleoNaoDependeDoSimulador = noClasses().that().resideInAnyPackage(
                    "br.gov.go.saude.fhir.safira.engine..", "br.gov.go.saude.fhir.safira.jades..",
                    "br.gov.go.saude.fhir.safira.steps..", "br.gov.go.saude.fhir.safira.rest..")
            .should().dependOnClassesThat().resideInAPackage("..safira.simulador..");

    @ArchTest
    static final ArchRule simuladorNaoDependeDaTruststoreNemDoApp = noClasses()
            .that().resideInAPackage("..safira.simulador..")
            .should().dependOnClassesThat().resideInAnyPackage("br.gov.go.saude.truststore..", "..safira.app..");
}
