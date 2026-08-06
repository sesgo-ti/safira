/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.validation;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome.Issue;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationContextTest {

    @Test
    void shouldExposeInputFieldsViaBuilder() {
        ValidationContext ctx = ValidationContext.builder()
                .signedDataBase64("ZXlKaGJHY2lPaUpTVXpJMU5pSjkuLi4u")
                .referenceTimestamp(1_765_000_000L)
                .policyIdentifierUri("https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0")
                .build();

        assertEquals("ZXlKaGJHY2lPaUpTVXpJMU5pSjkuLi4u", ctx.getSignedDataBase64());
        assertEquals(1_765_000_000L, ctx.getReferenceTimestamp());
        assertEquals(
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0",
                ctx.getPolicyIdentifierUri()
        );
    }

    @Test
    void shouldDefaultWarningsToEmptyMutableList() {
        ValidationContext ctx = ValidationContext.builder().build();

        assertNotNull(ctx.getWarnings());
        assertTrue(ctx.getWarnings().isEmpty());

        Issue issue = Issue.builder()
                .severity("warning")
                .code("informational")
                .diagnostics("sample")
                .build();

        ctx.getWarnings().add(issue);

        assertEquals(1, ctx.getWarnings().size());
        assertEquals(issue, ctx.getWarnings().get(0));
    }

    @Test
    void shouldPreserveAttributesAcrossToBuilder() {
        ValidationContext original = ValidationContext.builder()
                .attribute("key", "val")
                .build();

        ValidationContext rebuilt = original.toBuilder().build();

        Optional<String> value = rebuilt.getAttribute("key", String.class);
        assertTrue(value.isPresent());
        assertEquals("val", value.get());
    }

    @Test
    void shouldReturnEmptyOptionalWhenAttributeMissing() {
        ValidationContext ctx = ValidationContext.builder().build();

        Optional<String> value = ctx.getAttribute("missing", String.class);

        assertFalse(value.isPresent());
    }

    @Test
    void shouldReturnEmptyOptionalWhenAttributeTypeMismatch() {
        ValidationContext ctx = ValidationContext.builder()
                .attribute("port", 8080)
                .build();

        Optional<String> value = ctx.getAttribute("port", String.class);

        assertFalse(value.isPresent());
    }
}
