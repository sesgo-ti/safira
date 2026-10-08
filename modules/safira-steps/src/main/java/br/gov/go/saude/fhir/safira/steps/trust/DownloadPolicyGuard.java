/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig.DownloadPolicyConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.List;

/**
 * {@link DestinationGuard} dos downloads do DSS sobre a política de download da
 * icpbrasil-truststore ({@code icpbrasil-truststore.download-policy.*}).
 *
 * <p>Duas verificações, ambas pela {@link DownloadPolicy} da lib: o host da URL (allowlist de
 * domínios e nomes reservados, sem nova consulta DNS) e cada endereço efetivamente resolvido na
 * conexão (IP literal não público: loopback, RFC 1918, link-local, CGNAT, ULA...). A segunda
 * ignora a allowlist, que se aplica a nomes, e vale mesmo com {@code block-private-hostnames}
 * desligado — o endereço checado é o usado no socket.
 */
public final class DownloadPolicyGuard implements DestinationGuard {

    private final DownloadPolicy hostPolicy;
    private final DownloadPolicy addressPolicy;

    private DownloadPolicyGuard(DownloadPolicy hostPolicy, DownloadPolicy addressPolicy) {
        this.hostPolicy = hostPolicy;
        this.addressPolicy = addressPolicy;
    }

    public static DownloadPolicyGuard of(DownloadPolicyConfig config) {
        DownloadPolicyConfig host = copy(config);
        host.setBlockPrivateHostnames(false);
        DownloadPolicyConfig address = copy(config);
        address.setAllowedDomains(List.of());
        return new DownloadPolicyGuard(new DownloadPolicy(host), new DownloadPolicy(address));
    }

    @Override
    public void check(String host, InetAddress address) {
        hostPolicy.validateUrl("http://" + bracketed(host) + "/");
        String literal = address instanceof Inet6Address
                ? "[" + address.getHostAddress() + "]"
                : address.getHostAddress();
        addressPolicy.validateUrl("http://" + literal + "/");
    }

    private static String bracketed(String host) {
        return host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    private static DownloadPolicyConfig copy(DownloadPolicyConfig source) {
        DownloadPolicyConfig copy = new DownloadPolicyConfig();
        copy.setMaxOcspResponseBytes(source.getMaxOcspResponseBytes());
        copy.setMaxCrlResponseBytes(source.getMaxCrlResponseBytes());
        copy.setMaxAiaResponseBytes(source.getMaxAiaResponseBytes());
        copy.setBlockPrivateHostnames(source.isBlockPrivateHostnames());
        copy.setAllowedDomains(source.getAllowedDomains());
        return copy;
    }
}
