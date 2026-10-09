/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Fronteiras do produto: o núcleo (engine, jades, steps, rest) não conhece a icpbrasil-truststore nem o
 * simulador; núcleo e app não usam a PKI simulada do testkit; as camadas só dependem para baixo (engine e jades ← steps ← rest ← app); só o adaptador
 * {@code app.icpbrasil} usa a lib dentro do app. Importa somente classes de produção (sem {@code *-tests.jar}).
 */
@AnalyzeClasses(packages = "br.gov.go.saude",
        importOptions = {ImportOption.DoNotIncludeTests.class, ArquiteturaTest.SemTestJars.class})
class ArquiteturaTest {

    /** Exclui os {@code *-tests.jar} (ex.: auxiliares de teste do {@code safira-rest} no reactor). */
    static final class SemTestJars implements ImportOption {

        @Override
        public boolean includes(Location location) {
            return !location.contains("-tests.jar");
        }
    }

    private static final String[] NUCLEO = {
            "br.gov.go.saude.fhir.safira.engine..", "br.gov.go.saude.fhir.safira.jades..",
            "br.gov.go.saude.fhir.safira.steps..", "br.gov.go.saude.fhir.safira.rest.."};

    @ArchTest
    static final ArchRule nucleoNaoDependeDaTruststore = noClasses().that().resideInAnyPackage(NUCLEO)
            .should().dependOnClassesThat().resideInAPackage("br.gov.go.saude.truststore..");

    @ArchTest
    static final ArchRule nucleoNaoDependeDoSimulador = noClasses().that().resideInAnyPackage(NUCLEO)
            .should().dependOnClassesThat().resideInAPackage("..safira.simulador..");

    @ArchTest
    static final ArchRule nucleoEAppNaoDependemDoTestkit = noClasses()
            .that().resideInAnyPackage(NUCLEO).or().resideInAPackage("br.gov.go.saude.fhir.safira.app..")
            .should().dependOnClassesThat().resideInAPackage("..safira.testkit..");

    @ArchTest
    static final ArchRule engineNaoDependeDeCamadasSuperiores = noClasses()
            .that().resideInAPackage("..safira.engine..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "..safira.jades..", "..safira.steps..", "..safira.rest..", "..safira.app..");

    @ArchTest
    static final ArchRule jadesNaoDependeDeCamadasSuperiores = noClasses()
            .that().resideInAPackage("..safira.jades..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "..safira.engine..", "..safira.steps..", "..safira.rest..", "..safira.app..");

    @ArchTest
    static final ArchRule stepsNaoDependeDeRestNemApp = noClasses().that().resideInAPackage("..safira.steps..")
            .should().dependOnClassesThat().resideInAnyPackage("..safira.rest..", "..safira.app..");

    @ArchTest
    static final ArchRule restNaoDependeDoApp = noClasses().that().resideInAPackage("..safira.rest..")
            .should().dependOnClassesThat().resideInAPackage("..safira.app..");

    @ArchTest
    static final ArchRule appNaoDependeDoSimulador = noClasses().that().resideInAPackage("..safira.app..")
            .should().dependOnClassesThat().resideInAPackage("..safira.simulador..");

    @ArchTest
    static final ArchRule soAdaptadorIcpBrasilUsaATruststore = noClasses()
            .that().resideInAPackage("..safira.app..").and().resideOutsideOfPackage("..safira.app.icpbrasil..")
            .should().dependOnClassesThat().resideInAPackage("br.gov.go.saude.truststore..");
}
