/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class SignatureExceptionCodeTest {

    private static final List<String> CODESYSTEM_020_NEW = List.of(
            "CACHE.UNAVAILABLE", "FORMAT.JADES-COMPONENT-PLACEMENT-INVALID",
            "FORMAT.JADES-UNPROTECTED-HEADER-INVALID", "POLICY.SIGNATURE-POLICY-ID-INVALID",
            "REVOCATION.STATUS-UNKNOWN", "TEMPORAL.IAT-MISSING", "TSA.CERTIFICATE-PURPOSE-INVALID",
            "TSA.CERTIFICATE-REVOKED", "TSA.CERTIFICATE-TIME-INVALID", "TSA.CHAIN-VALIDATION-FAILED",
            "TSA.MESSAGE-IMPRINT-MISMATCH", "TSA.POLICY-UNSUPPORTED", "TSA.SIGNATURE-INVALID",
            "VALIDATION.INDETERMINATE", "VALIDATION.JADES-LEVEL-INVALID", "VALIDATION.TRY-LATER");

    @Test
    void shouldContainEveryCodeIntroducedByCodeSystem020() {
        Set<String> codes = Arrays.stream(SignatureExceptionCode.values())
                .map(SignatureExceptionCode::getCode)
                .collect(Collectors.toSet());

        assertThat(codes).containsAll(CODESYSTEM_020_NEW);
    }

    @Test
    void shouldDeclareCodeSystemVersion020() {
        assertThat(SignatureExceptionCode.SYSTEM_VERSION).isEqualTo("0.2.0");
    }

    @Test
    void shouldMarkIndeterminateOutcomesAsWarning() {
        assertThat(SignatureExceptionCode.VALIDATION_INDETERMINATE.getSeverity()).isEqualTo("warning");
    }
}
