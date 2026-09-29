/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.json;

import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNumber;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LosslessJsonTest {

    @Test
    void shouldPreserveDecimalLexicalTokens() {
        String json = "{\"a\":2.00,\"b\":1.0e2,\"c\":-0.0,\"d\":10}";

        assertThat(LosslessJson.write(LosslessJson.parse(json))).isEqualTo(json);
    }

    @Test
    void shouldExposeNumberLexicalToken() {
        JsonObject object = LosslessJson.parseObject("{\"value\":1.50E+3}");

        assertThat(object.get("value")).contains(new JsonNumber("1.50E+3"));
    }

    @Test
    void shouldRejectDuplicateMembers() {
        assertThatThrownBy(() -> LosslessJson.parse("{\"a\":1,\"a\":2}"))
                .isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldRejectDuplicateMembersInNestedObjects() {
        assertThatThrownBy(() -> LosslessJson.parse("{\"a\":[{\"b\":1,\"b\":1}]}"))
                .isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldRejectTrailingContent() {
        assertThatThrownBy(() -> LosslessJson.parse("{} {}"))
                .isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldRejectLoneSurrogate() {
        assertThatThrownBy(() -> LosslessJson.parse("{\"a\":\"\\uD800\"}"))
                .isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldAcceptSurrogatePair() {
        JsonObject object = LosslessJson.parseObject("{\"a\":\"\\uD83D\\uDE00\"}");

        assertThat(object.get("a")).contains(new JsonString("\uD83D\uDE00"));
    }

    @Test
    void shouldRejectNonObjectRootWhenObjectRequired() {
        assertThatThrownBy(() -> LosslessJson.parseObject("[1]"))
                .isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldPreserveMemberOrderWhenWriting() {
        String json = "{\"z\":1,\"a\":{\"y\":true,\"b\":null},\"m\":[3,\"x\"]}";

        assertThat(LosslessJson.write(LosslessJson.parse(json))).isEqualTo(json);
    }

    @Test
    void shouldEscapeControlCharactersAsRfc8785() {
        JsonObject object = LosslessJson.parseObject("{\"a\":\"\\u0001\\n\\\"\\\\\\/é\\u001F\"}");

        assertThat(LosslessJson.write(object)).isEqualTo("{\"a\":\"\\u0001\\n\\\"\\\\/é\\u001f\"}");
    }

    @Test
    void shouldReplaceMemberKeepingPosition() {
        JsonObject object = LosslessJson.parseObject("{\"a\":1,\"b\":2,\"c\":3}");

        JsonObject changed = object.with("b", new JsonString("x"));

        assertThat(LosslessJson.write(changed)).isEqualTo("{\"a\":1,\"b\":\"x\",\"c\":3}");
    }

    @Test
    void shouldRemoveMembersWithoutTouchingOriginal() {
        JsonObject object = LosslessJson.parseObject("{\"a\":1,\"b\":2}");

        JsonObject changed = object.without("a");

        assertThat(LosslessJson.write(changed)).isEqualTo("{\"b\":2}");
        assertThat(LosslessJson.write(object)).isEqualTo("{\"a\":1,\"b\":2}");
    }
}
