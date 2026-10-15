/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import org.apache.hc.client5.http.DnsResolver;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/** {@link DnsResolver} que submete todo endereço resolvido ao {@link DestinationGuard}. */
final class GuardedDnsResolver implements DnsResolver {

    private final DnsResolver delegate;
    private final DestinationGuard guard;

    GuardedDnsResolver(DnsResolver delegate, DestinationGuard guard) {
        this.delegate = delegate;
        this.guard = guard;
    }

    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        InetAddress[] addresses = delegate.resolve(host);
        for (InetAddress address : addresses) {
            try {
                guard.check(host, address);
            } catch (RuntimeException e) {
                UnknownHostException refused = new UnknownHostException(
                        "Destino recusado: " + host + " (" + address.getHostAddress() + "): " + e.getMessage());
                refused.initCause(e);
                throw refused;
            }
        }
        return addresses;
    }

    @Override
    public List<InetSocketAddress> resolve(String host, int port) throws UnknownHostException {
        return Arrays.stream(resolve(host)).map(address -> new InetSocketAddress(address, port)).toList();
    }

    @Override
    public String resolveCanonicalHostname(String host) throws UnknownHostException {
        return delegate.resolveCanonicalHostname(host);
    }
}
