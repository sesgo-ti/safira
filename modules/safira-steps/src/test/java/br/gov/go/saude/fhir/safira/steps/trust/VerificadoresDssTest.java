/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class VerificadoresDssTest {

    private static TestPki pki;
    private static TestPki other;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        other = TestPki.create();
    }

    private static AcervoDeConfianca acervo(String geracao, TestPki source) {
        return new AcervoDeConfianca(geracao, List.of(source.caCert), List.of(source.tsaCert));
    }

    private static VerificadoresDss verificadores(AtomicReference<AcervoDeConfianca> atual) {
        return new VerificadoresDss(() -> Optional.ofNullable(atual.get()), CertificateVerifierFactory.offline(null, null));
    }

    private static CommonCertificateVerifier verificador(VerificadoresDss verificadores) {
        return verificadores.paraOperacao(List.of()).orElseThrow();
    }

    private static boolean cadeiaConfiavel(X509Certificate leaf, CommonCertificateVerifier verifier) {
        CertificateReports reports = new CertificateValidationService().validate(leaf, List.of(), verifier);
        return reports.getDiagnosticData().getUsedCertificateById(new CertificateToken(leaf).getDSSIdAsString())
                .isTrustedChain();
    }

    @Test
    void shouldReuseDssSourcesWhileGenerationIsUnchanged() {
        AtomicReference<AcervoDeConfianca> atual = new AtomicReference<>(acervo("g1", pki));
        VerificadoresDss verificadores = verificadores(atual);
        Object primeira = verificador(verificadores).getTrustedCertSources().getSources().getFirst();
        atual.set(acervo("g1", pki));

        assertThat(verificador(verificadores).getTrustedCertSources().getSources().getFirst()).isSameAs(primeira);
    }

    @Test
    void shouldRebuildDssSourcesWhenGenerationChanges() {
        AtomicReference<AcervoDeConfianca> atual = new AtomicReference<>(acervo("g1", pki));
        VerificadoresDss verificadores = verificadores(atual);
        Object primeira = verificador(verificadores).getTrustedCertSources().getSources().getFirst();
        atual.set(acervo("g2", other));

        CommonCertificateVerifier verifier = verificador(verificadores);

        assertThat(verifier.getTrustedCertSources().getSources().getFirst()).isNotSameAs(primeira);
        assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(other.caCert));
    }

    @Test
    void shouldReturnEmptyWhenTrustIsUnavailable() {
        assertThat(verificadores(new AtomicReference<>()).paraOperacao(List.of())).isEmpty();
    }

    @Test
    void shouldKeepOnlyRootsAsTrustedAndCasAsAdjunct() {
        CommonCertificateVerifier verifier = verificador(verificadores(new AtomicReference<>(acervo("g1", pki))));

        assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(pki.caCert));
        assertThat(verifier.getAdjunctCertSources().getCertificates()).containsExactly(new CertificateToken(pki.tsaCert));
    }

    @Test
    void shouldAddExtraAnchorsOnlyToThatOperation() {
        VerificadoresDss verificadores = verificadores(new AtomicReference<>(acervo("g1", pki)));

        assertThat(verificadores.paraOperacao(List.of(other.caCert)).orElseThrow().getTrustedCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.caCert), new CertificateToken(other.caCert));
        assertThat(verificador(verificadores).getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.caCert));
    }

    @Test
    void shouldKeepGenerationOfVerifierWhenAcervoChangesDuringOperation() {
        AtomicReference<AcervoDeConfianca> atual = new AtomicReference<>(acervo("g1", pki));
        VerificadoresDss verificadores = verificadores(atual);
        CommonCertificateVerifier obtido = verificador(verificadores);
        atual.set(acervo("g2", other));
        verificador(verificadores);

        assertThat(cadeiaConfiavel(pki.leafCert, obtido)).isTrue();
        assertThat(cadeiaConfiavel(other.leafCert, obtido)).isFalse();
    }

    @Test
    void shouldAskTrustSourceOncePerOperation() {
        AtomicInteger chamadas = new AtomicInteger();
        VerificadoresDss verificadores = new VerificadoresDss(() -> {
            chamadas.incrementAndGet();
            return Optional.of(acervo("g1", pki));
        }, CertificateVerifierFactory.offline(null, null));

        verificadores.paraOperacao(List.of(other.caCert));

        assertThat(chamadas).hasValue(1);
    }

    @Test
    void shouldNeverMixGenerationsWhenCalledConcurrently() throws Exception {
        AcervoDeConfianca g1 = acervo("g1", pki);
        AcervoDeConfianca g2 = acervo("g2", other);
        AtomicReference<AcervoDeConfianca> atual = new AtomicReference<>(g1);
        ThreadLocal<AcervoDeConfianca> entregue = new ThreadLocal<>();
        VerificadoresDss verificadores = new VerificadoresDss(() -> {
            AcervoDeConfianca acervo = atual.get();
            entregue.set(acervo);
            return Optional.of(acervo);
        }, CertificateVerifierFactory.offline(null, null));
        AtomicBoolean rodando = new AtomicBoolean(true);
        ExecutorService executor = Executors.newFixedThreadPool(9);
        try {
            Future<?> alternador = executor.submit(() -> {
                while (rodando.get()) {
                    atual.set(atual.get() == g1 ? g2 : g1);
                }
            });
            List<Callable<List<List<CertificateToken>>>> tarefas = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                tarefas.add(() -> {
                    List<List<CertificateToken>> divergentes = new ArrayList<>();
                    for (int n = 0; n < 300; n++) {
                        CommonCertificateVerifier verifier = verificador(verificadores);
                        List<CertificateToken> obtido = new ArrayList<>(verifier.getTrustedCertSources().getCertificates());
                        obtido.addAll(verifier.getAdjunctCertSources().getCertificates());
                        AcervoDeConfianca esperado = entregue.get();
                        if (!obtido.equals(List.of(new CertificateToken(esperado.raizes().getFirst()),
                                new CertificateToken(esperado.intermediarias().getFirst())))) {
                            divergentes.add(obtido);
                        }
                    }
                    return divergentes;
                });
            }
            List<List<CertificateToken>> divergentes = new ArrayList<>();
            for (Future<List<List<CertificateToken>>> resultado : executor.invokeAll(tarefas)) {
                divergentes.addAll(resultado.get());
            }
            rodando.set(false);
            alternador.get();

            assertThat(divergentes).isEmpty();
        } finally {
            rodando.set(false);
            executor.shutdownNow();
            executor.awaitTermination(10, TimeUnit.SECONDS);
        }
    }
}
