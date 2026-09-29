/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class FhirLosslessCanonicalizerTest {

    private static String canonical(String json) {
        return new String(FhirLosslessCanonicalizer.canonicalize(LosslessJson.parseObject(json)),
                StandardCharsets.UTF_8);
    }

    @Test
    void shouldRemoveOnlyRootIdAndEnumeratedMetaMembers() {
        String input = "{\"resourceType\":\"Observation\",\"id\":\"x\",\"_id\":{\"extension\":[]},"
                + "\"meta\":{\"versionId\":\"1\",\"_versionId\":{},\"lastUpdated\":\"2025-01-01T00:00:00Z\","
                + "\"_lastUpdated\":{},\"source\":\"s\",\"_source\":{},\"tag\":[],\"profile\":[\"p\"]},"
                + "\"contained\":[{\"resourceType\":\"Patient\",\"id\":\"p1\",\"meta\":{\"versionId\":\"9\"}}],"
                + "\"valueQuantity\":{\"value\":2.00}}";

        assertThat(canonical(input)).isEqualTo(
                "{\"contained\":[{\"id\":\"p1\",\"meta\":{\"versionId\":\"9\"},\"resourceType\":\"Patient\"}],"
                        + "\"meta\":{\"profile\":[\"p\"]},\"resourceType\":\"Observation\","
                        + "\"valueQuantity\":{\"value\":2.00}}");
    }

    @Test
    void shouldOmitMetaWhenEmptyAfterRemovals() {
        assertThat(canonical("{\"resourceType\":\"Patient\",\"meta\":{\"versionId\":\"1\",\"tag\":[]}}"))
                .isEqualTo("{\"resourceType\":\"Patient\"}");
    }

    @Test
    void shouldKeepMetaSecurityAndNestedElementIds() {
        assertThat(canonical("{\"resourceType\":\"Patient\",\"meta\":{\"security\":[]},"
                + "\"name\":[{\"id\":\"n1\",\"family\":\"Silva\"}]}"))
                .isEqualTo("{\"meta\":{\"security\":[]},\"name\":[{\"family\":\"Silva\",\"id\":\"n1\"}],"
                        + "\"resourceType\":\"Patient\"}");
    }

    @Test
    void shouldSortMembersByUtf16CodeUnits() {
        // U+1F600 (surrogates D83D DE00) antecede U+E000 na ordem de unidades UTF-16
        assertThat(canonical("{\"\":1,\"😀\":2}"))
                .isEqualTo("{\"😀\":2,\"\":1}");
    }

    @Test
    void shouldKeepExponentDecimalLexically() {
        assertThat(canonical("{\"resourceType\":\"Observation\",\"valueDecimal\":1.0e2}"))
                .isEqualTo("{\"resourceType\":\"Observation\",\"valueDecimal\":1.0e2}");
    }

    @Test
    void shouldPreserveArrayOrder() {
        assertThat(canonical("{\"a\":[3,1,2]}")).isEqualTo("{\"a\":[3,1,2]}");
    }

    @Test
    void shouldEncodeNonAsciiAsUtf8() {
        byte[] bytes = FhirLosslessCanonicalizer.canonicalize(LosslessJson.parseObject("{\"a\":\"é\"}"));

        assertThat(bytes).containsExactly('{', '"', 'a', '"', ':', '"', 0xC3, 0xA9, '"', '}');
    }
}
