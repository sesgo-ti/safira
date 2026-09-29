/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

import java.util.Optional;

/** Faixas admitidas das configurações operacionais (criar 1.11; validar seção 0). */
public final class OperationalChecks {

    private OperationalChecks() {
    }

    public static Optional<PolicyViolation> check(SafiraOperationalConfigProperties config) {
        if (config == null) {
            return fail(SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "Configurações operacionais ausentes.");
        }
        var verification = config.verification();
        if (verification != null) {
            if (outside(verification.ocspCacheTtl(), 300, 86400) || outside(verification.crlCacheTtl(), 300, 86400)) {
                return fail(SignatureExceptionCode.CONFIG_TTL_OUT_OF_RANGE, "TTL de cache de revogação fora de [300, 86400].");
            }
            if (outside(verification.ocspTimeout(), 5, 120) || outside(verification.crlTimeout(), 5, 120)
                    || outside(verification.tsaTimeout(), 5, 120)) {
                return fail(SignatureExceptionCode.CONFIG_TIMEOUT_OUT_OF_RANGE, "Timeout de verificação fora de [5, 120].");
            }
        }
        var security = config.security();
        if (security != null) {
            if (outside(security.maxEntriesBundle(), 100, 10000)) {
                return fail(SignatureExceptionCode.CONFIG_BUNDLE_SIZE_LIMIT_OUT_OF_RANGE, "maxEntriesBundle fora de [100, 10000].");
            }
            if (outside(security.maxBundleSize(), 1048576, 209715200)) {
                return fail(SignatureExceptionCode.CONFIG_BUNDLE_MEMORY_LIMIT_OUT_OF_RANGE,
                        "maxBundleBytes fora de [1048576, 209715200].");
            }
            if (outside(security.timoutVerificationBundle(), 5, 300)) {
                return fail(SignatureExceptionCode.CONFIG_BUNDLE_TIMEOUT_OUT_OF_RANGE, "bundleVerifyTimeout fora de [5, 300].");
            }
        }
        return Optional.empty();
    }

    private static boolean outside(Integer value, int min, int max) {
        return value != null && (value < min || value > max);
    }

    private static Optional<PolicyViolation> fail(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
