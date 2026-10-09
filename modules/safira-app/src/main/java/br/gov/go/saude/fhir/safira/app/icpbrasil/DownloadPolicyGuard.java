/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig.DownloadPolicyConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

/**
 * {@link DestinationGuard} dos downloads do DSS sobre a política de download da
 * icpbrasil-truststore ({@code icpbrasil-truststore.download-policy.*}).
 *
 * <p>Duas verificações, ambas pela {@link DownloadPolicy} da lib: o host da URL (allowlist de
 * domínios e nomes reservados, sem nova consulta DNS) e cada endereço efetivamente resolvido na
 * conexão (IP literal não público: loopback, RFC 1918, link-local, CGNAT, ULA...). A segunda
 * ignora a allowlist, que se aplica a nomes, e vale mesmo com {@code block-private-hostnames}
 * desligado — o endereço checado é o usado no socket.
 *
 * <p>Endereços IPv6 de transição que embutem IPv4 escapam da classificação da lib: o IPv4 de
 * IPv4-compatible ({@code ::/96}), NAT64 ({@code 64:ff9b::/96}) e 6to4 ({@code 2002::/16}) passa
 * pela mesma política; NAT64 de uso local ({@code 64:ff9b:1::/48}) e Teredo ({@code 2001::/32})
 * são recusados.
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
        if (address instanceof Inet6Address) {
            addressPolicy.validateUrl("http://[" + address.getHostAddress() + "]/");
            embeddedIpv4(address.getAddress())
                    .ifPresent(ipv4 -> addressPolicy.validateUrl("http://" + ipv4 + "/"));
        } else {
            addressPolicy.validateUrl("http://" + address.getHostAddress() + "/");
        }
    }

    /** IPv4 embutido em prefixos de transição; recusa os prefixos sem destino público legítimo. */
    private static Optional<String> embeddedIpv4(byte[] octets) {
        if (startsWith(octets, 0x00, 0x64, 0xff, 0x9b, 0x00, 0x01)) {
            throw new DownloadPolicyException("NAT64 de uso local (64:ff9b:1::/48) bloqueado.");
        }
        if (startsWith(octets, 0x20, 0x01, 0x00, 0x00)) {
            throw new DownloadPolicyException("Teredo (2001::/32) bloqueado.");
        }
        if (startsWith(octets, 0x20, 0x02)) {
            return Optional.of(ipv4(octets, 2));
        }
        if (startsWith(octets, 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0)
                || startsWith(octets, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) {
            return Optional.of(ipv4(octets, 12));
        }
        return Optional.empty();
    }

    private static boolean startsWith(byte[] octets, int... prefix) {
        for (int i = 0; i < prefix.length; i++) {
            if ((octets[i] & 0xFF) != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static String ipv4(byte[] octets, int offset) {
        return (octets[offset] & 0xFF) + "." + (octets[offset + 1] & 0xFF) + "."
                + (octets[offset + 2] & 0xFF) + "." + (octets[offset + 3] & 0xFF);
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
