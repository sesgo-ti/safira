/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TsaTrustStoresTest {

    static Path writePem(Path dir, X509Certificate... certificates) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(certificate.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        Path file = Files.createTempFile(dir, "tsa-anchors", ".pem");
        Files.writeString(file, pem, StandardCharsets.US_ASCII);
        return file;
    }

    @Test
    void shouldLoadPemBundleFromFile(@TempDir Path dir) throws Exception {
        TestPki pki = TestPki.create();
        Path file = writePem(dir, pki.caCert, pki.tsaCert);

        assertThat(TsaTrustStores.load("file:" + file)).containsExactly(pki.caCert, pki.tsaCert);
    }

    @Test
    void shouldAcceptPlainPath(@TempDir Path dir) throws Exception {
        TestPki pki = TestPki.create();
        Path file = writePem(dir, pki.caCert);

        assertThat(TsaTrustStores.load(file.toString())).containsExactly(pki.caCert);
    }

    @Test
    void shouldRejectEmptyBundle(@TempDir Path dir) throws Exception {
        Path file = Files.createTempFile(dir, "empty", ".pem");

        assertThatThrownBy(() -> TsaTrustStores.load("file:" + file))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectMissingClasspathResource() {
        assertThatThrownBy(() -> TsaTrustStores.load("classpath:nao-existe.pem"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
