/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/** A CLI fica no topo: núcleo, app e simulador não a conhecem. Só classes de produção. */
@AnalyzeClasses(packages = "br.gov.go.saude.fhir.safira",
        importOptions = {ImportOption.DoNotIncludeTests.class, ArquiteturaCliTest.SemTestJars.class})
class ArquiteturaCliTest {

    static final class SemTestJars implements ImportOption {

        @Override
        public boolean includes(Location location) {
            return !location.contains("-tests.jar");
        }
    }

    @ArchTest
    static final ArchRule nucleoNaoDependeDaCli = noClasses().that().resideInAnyPackage(
                    "..safira.engine..", "..safira.jades..", "..safira.steps..", "..safira.rest..")
            .should().dependOnClassesThat().resideInAPackage("..safira.cli..");

    @ArchTest
    static final ArchRule appESimuladorNaoDependemDaCli = noClasses().that().resideInAnyPackage(
                    "..safira.app..", "..safira.simulador..", "..safira.testkit..")
            .should().dependOnClassesThat().resideInAPackage("..safira.cli..");
}
