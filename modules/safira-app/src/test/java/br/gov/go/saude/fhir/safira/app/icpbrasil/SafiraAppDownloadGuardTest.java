/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

import br.gov.go.saude.fhir.safira.engine.config.SafiraEngineAutoConfiguration;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A {@link CertificateVerifierFactory} montada pela aplicação usa o {@link DownloadPolicyGuard}: um download
 * do DSS para um endereço interno é recusado antes de qualquer conexão.
 */
class SafiraAppDownloadGuardTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraEngineAutoConfiguration.class,
                    TrustStoreAutoConfiguration.class, SafiraIcpBrasilAutoConfiguration.class,
                    SafiraStepsAutoConfiguration.class))
            .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                    "icpbrasil-truststore.scheduling.enabled=false",
                    "icpbrasil-truststore.filesystem.base-dir=target/icpbrasil-truststore-download-guard");

    @Test
    void shouldRefuseCrlDownloadToLoopbackWithoutConnectingWhenFactoryIsWiredByApp() {
        runner.run(context -> {
            CommonCertificateVerifier verifier = verifier(context.getBean(CertificateVerifierFactory.class));
            assertRefusedWithoutConnection(dataLoader(verifier.getCrlSource()));
        });
    }

    @Test
    void shouldRefuseOcspDownloadToLoopbackWithoutConnectingWhenFactoryIsWiredByApp() {
        runner.run(context -> {
            CommonCertificateVerifier verifier = verifier(context.getBean(CertificateVerifierFactory.class));
            assertRefusedWithoutConnection(dataLoader(verifier.getOcspSource()));
        });
    }

    private static CommonCertificateVerifier verifier(CertificateVerifierFactory factory) {
        return factory.create(CertificateVerifierFactory.acervo(List.of(), List.of()), List.of());
    }

    /** O DSS não expõe o data loader das fontes online; lê-se o campo para exercitar o loader realmente montado. */
    private static DataLoader dataLoader(Object onlineSource) {
        return (DataLoader) ReflectionTestUtils.getField(onlineSource, "dataLoader");
    }

    private static void assertRefusedWithoutConnection(DataLoader loader) throws IOException, InterruptedException {
        try (ServerSocket server = new ServerSocket(0)) {
            AtomicBoolean accepted = new AtomicBoolean();
            Thread acceptor = Thread.ofVirtual().start(() -> {
                try {
                    server.accept().close();
                    accepted.set(true);
                } catch (IOException encerrado) {
                    // socket fechado ao fim do teste
                }
            });
            String url = "http://127.0.0.1:" + server.getLocalPort() + "/";

            assertThatThrownBy(() -> loader.get(url)).hasRootCauseInstanceOf(DownloadPolicyException.class);

            server.close();
            acceptor.join();
            assertThat(accepted).isFalse();
        }
    }
}
