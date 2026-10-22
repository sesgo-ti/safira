/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/** Verificações de entrada comuns à criação (1.1, 1.2, 1.10) e à validação (seção 0). */
public final class PolicyChecks {

    private static final String SEMVER_SEGMENT = "\\d+\\.\\d+\\.\\d+";

    private PolicyChecks() {
    }

    /** URI absoluta HTTPS, sem fragmento nem separador {@code |}, terminada em versão, igual à 0.2.0. */
    public static Optional<PolicyViolation> policyUri(String policyUri) {
        if (policyUri == null || policyUri.isBlank()) {
            return violation(SignatureExceptionCode.POLICY_MISSING, "Política de assinatura não informada.");
        }
        URI uri;
        try {
            uri = new URI(policyUri);
        } catch (URISyntaxException e) {
            return violation(SignatureExceptionCode.POLICY_URI_INVALID, "URI da política inválida (RFC 3986): " + policyUri);
        }
        String path = uri.getPath();
        String lastSegment = path == null ? "" : path.substring(path.lastIndexOf('/') + 1);
        if (!uri.isAbsolute() || !"https".equals(uri.getScheme()) || uri.getFragment() != null
                || policyUri.contains("|") || !lastSegment.matches(SEMVER_SEGMENT)) {
            return violation(SignatureExceptionCode.POLICY_URI_INVALID,
                    "A política deve ser uma URI HTTPS absoluta terminada no segmento de versão major.minor.patch: "
                            + policyUri);
        }
        if (!Policy020.POLICY_URI.equals(policyUri)) {
            return violation(SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED,
                    "Política solicitada " + policyUri + " não suportada; versão contemplada: " + Policy020.POLICY_URI);
        }
        return Optional.empty();
    }

    /**
     * Timestamp de referência presente, na faixa da política e a no máximo
     * {@link Policy020#CLOCK_TOLERANCE_SECONDS} do relógio do servidor.
     */
    public static Optional<PolicyViolation> referenceTimestamp(Long timestamp, long nowEpochSeconds) {
        if (timestamp == null) {
            return violation(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT,
                    "Timestamp de referência ausente ou não inteiro.");
        }
        if (timestamp < Policy020.MIN_TIMESTAMP || timestamp > Policy020.MAX_TIMESTAMP) {
            return violation(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP,
                    "Timestamp de referência fora do intervalo [1751328000, 4102444800].");
        }
        // DIVERGENCIA-IG D2/D8: o instante vem da requisição, limitado a ±300 s do relógio do servidor
        if (Math.abs(timestamp - nowEpochSeconds) > Policy020.CLOCK_TOLERANCE_SECONDS) {
            return violation(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP,
                    "Timestamp de referência difere mais de 300 segundos do relógio do servidor.");
        }
        return Optional.empty();
    }

    private static Optional<PolicyViolation> violation(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
