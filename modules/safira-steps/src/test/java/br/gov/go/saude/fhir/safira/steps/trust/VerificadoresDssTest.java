/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
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

    private static PkiIcpSimulada pki;
    private static PkiIcpSimulada other;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        other = PkiIcpSimulada.criar();
    }

    private static AcervoDeConfianca acervo(String geracao, PkiIcpSimulada source) {
        return new AcervoDeConfianca(geracao, List.of(source.raiz()), List.of(source.ac(), source.tsa()));
    }

    private static VerificadoresDss verificadores(AtomicReference<AcervoDeConfianca> atual) {
        return new VerificadoresDss(() -> Optional.ofNullable(atual.get()), CertificateVerifierFactory.offline(null, null));
    }

    private static CommonCertificateVerifier verificador(VerificadoresDss verificadores) {
        return verificador(verificadores, List.of());
    }

    private static CommonCertificateVerifier verificador(VerificadoresDss verificadores, List<X509Certificate> extras) {
        return verificadores.paraOperacao(verificadores.acervoAtual().orElseThrow(), extras);
    }

    private static boolean cadeiaConfiavel(PkiIcpSimulada fonte, CommonCertificateVerifier verifier) {
        X509Certificate leaf = fonte.signatario();
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
        assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(other.raiz()));
    }

    @Test
    void shouldReturnEmptyWhenTrustIsUnavailable() {
        assertThat(verificadores(new AtomicReference<>()).acervoAtual()).isEmpty();
    }

    @Test
    void shouldKeepOnlyRootsAsTrustedAndCasAsAdjunct() {
        CommonCertificateVerifier verifier = verificador(verificadores(new AtomicReference<>(acervo("g1", pki))));

        assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(pki.raiz()));
        assertThat(verifier.getAdjunctCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.ac()), new CertificateToken(pki.tsa()));
    }

    @Test
    void shouldAddExtraAnchorsOnlyToThatOperation() {
        VerificadoresDss verificadores = verificadores(new AtomicReference<>(acervo("g1", pki)));

        assertThat(verificador(verificadores, List.of(other.raiz())).getTrustedCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.raiz()), new CertificateToken(other.raiz()));
        assertThat(verificador(verificadores).getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.raiz()));
    }

    @Test
    void shouldKeepGenerationOfVerifierWhenAcervoChangesDuringOperation() {
        AtomicReference<AcervoDeConfianca> atual = new AtomicReference<>(acervo("g1", pki));
        VerificadoresDss verificadores = verificadores(atual);
        CommonCertificateVerifier obtido = verificador(verificadores);
        atual.set(acervo("g2", other));
        verificador(verificadores);

        assertThat(cadeiaConfiavel(pki, obtido)).isTrue();
        assertThat(cadeiaConfiavel(other, obtido)).isFalse();
    }

    @Test
    void shouldAskTrustSourceOncePerOperation() {
        AtomicInteger chamadas = new AtomicInteger();
        VerificadoresDss verificadores = new VerificadoresDss(() -> {
            chamadas.incrementAndGet();
            return Optional.of(acervo("g1", pki));
        }, CertificateVerifierFactory.offline(null, null));

        verificador(verificadores, List.of(other.raiz()));

        assertThat(chamadas).hasValue(1);
    }

    /** Teste de fumaça: a intercalação das threads não é determinística. */
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
                    Thread.onSpinWait();
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
                        List<CertificateToken> esperados = new ArrayList<>(List.of(new CertificateToken(esperado.raizes().getFirst())));
                        esperado.intermediarias().forEach(certificado -> esperados.add(new CertificateToken(certificado)));
                        if (obtido.size() != esperados.size() || !new HashSet<>(obtido).equals(new HashSet<>(esperados))) {
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
