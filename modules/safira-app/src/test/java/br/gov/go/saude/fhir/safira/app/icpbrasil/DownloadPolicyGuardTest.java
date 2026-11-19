/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

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

    @ParameterizedTest
    @ValueSource(strings = {"::7f00:1", "::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:a00:1::1",
            "2002:7f00:1::", "64:ff9b:1::808:808", "2001:0:4136:e378:8000:63bf:3fff:fdd2"})
    void shouldRefuseTransitionAddressWhenItEmbedsInternalIpv4OrIsLocalOnly(String literal) {
        assertThatThrownBy(() -> guard().check("ocsp.example.com", ip(literal))).isInstanceOf(DownloadPolicyException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"64:ff9b::c8c6:1", "2002:c8c6:1::1", "2804:214::1"})
    void shouldAcceptIpv6WhenEmbeddedIpv4IsPublicOrAbsent(String literal) {
        assertThatCode(() -> guard().check("ocsp.example.com", ip(literal))).doesNotThrowAnyException();
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
