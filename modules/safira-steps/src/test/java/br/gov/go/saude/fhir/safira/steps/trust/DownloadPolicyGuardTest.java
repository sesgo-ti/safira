/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig.DownloadPolicyConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DownloadPolicyGuardTest {

    private static InetAddress ip(String literal) throws UnknownHostException {
        return InetAddress.getByName(literal);
    }

    private static DownloadPolicyGuard guard() {
        return DownloadPolicyGuard.of(new DownloadPolicyConfig());
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "fd00::1"})
    void shouldRefuseInternalAddressWhenUrlIsLiteral(String literal) throws UnknownHostException {
        assertThatThrownBy(() -> guard().check(literal, ip(literal))).isInstanceOf(DownloadPolicyException.class);
    }

    @Test
    void shouldRefuseHostnameWhenItResolvesToInternalAddress() {
        assertThatThrownBy(() -> guard().check("ocsp.example.com", ip("10.0.0.1")))
                .isInstanceOf(DownloadPolicyException.class);
    }

    @Test
    void shouldRefuseReservedHostnameWhenRequested() {
        assertThatThrownBy(() -> guard().check("localhost", ip("127.0.0.1"))).isInstanceOf(DownloadPolicyException.class);
    }

    @Test
    void shouldAcceptPublicAddressWhenHostnameResolvesToIt() {
        assertThatCode(() -> guard().check("ocsp.example.com", ip("200.198.0.1"))).doesNotThrowAnyException();
    }

    @Test
    void shouldRefuseHostOutsideAllowlistWhenAllowlistIsConfigured() {
        DownloadPolicyConfig config = new DownloadPolicyConfig();
        config.setAllowedDomains(List.of("icpbrasil.gov.br"));

        assertThatThrownBy(() -> DownloadPolicyGuard.of(config).check("ocsp.example.com", ip("200.198.0.1")))
                .isInstanceOf(DownloadPolicyException.class);
    }

    @Test
    void shouldAcceptAllowlistedHostWhenItResolvesToPublicAddress() {
        DownloadPolicyConfig config = new DownloadPolicyConfig();
        config.setAllowedDomains(List.of("icpbrasil.gov.br"));

        assertThatCode(() -> DownloadPolicyGuard.of(config).check("lcr.icpbrasil.gov.br", ip("200.198.0.1")))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldKeepBlockingInternalAddressWhenPrivateHostnameCheckIsDisabled() {
        DownloadPolicyConfig config = new DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);

        assertThatThrownBy(() -> DownloadPolicyGuard.of(config).check("ocsp.example.com", ip("10.0.0.1")))
                .isInstanceOf(DownloadPolicyException.class);
    }
}
