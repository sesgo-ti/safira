/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.json;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Árvore JSON imutável e sem perda: objetos preservam a ordem dos membros e números
 * preservam o token lexical recebido (ex.: {@code 2.00}, {@code 1.0e2}).
 *
 * <p>Exigida pela canonicalização {@code fhir-json-lossless} da política 0.2.0, que proíbe
 * converter elementos FHIR {@code decimal} para ponto flutuante.
 */
public sealed interface JsonValue {

    /** Objeto JSON; os membros mantêm a ordem de inserção. */
    record JsonObject(Map<String, JsonValue> members) implements JsonValue {

        public JsonObject {
            members = Collections.unmodifiableMap(new LinkedHashMap<>(members));
        }

        public Optional<JsonValue> get(String name) {
            return Optional.ofNullable(members.get(name));
        }

        public Optional<String> string(String name) {
            return get(name).filter(JsonString.class::isInstance).map(v -> ((JsonString) v).value());
        }

        public Optional<JsonObject> object(String name) {
            return get(name).filter(JsonObject.class::isInstance).map(JsonObject.class::cast);
        }

        public Optional<JsonArray> array(String name) {
            return get(name).filter(JsonArray.class::isInstance).map(JsonArray.class::cast);
        }

        /** Cópia com o membro substituído (mesma posição) ou acrescentado ao final. */
        public JsonObject with(String name, JsonValue value) {
            Map<String, JsonValue> copy = new LinkedHashMap<>(members);
            copy.put(name, Objects.requireNonNull(value, "value"));
            return new JsonObject(copy);
        }

        /** Cópia sem os membros informados. */
        public JsonObject without(String... names) {
            Map<String, JsonValue> copy = new LinkedHashMap<>(members);
            for (String name : names) {
                copy.remove(name);
            }
            return new JsonObject(copy);
        }

        public Set<String> names() {
            return members.keySet();
        }
    }

    record JsonArray(List<JsonValue> items) implements JsonValue {

        public JsonArray {
            items = List.copyOf(items);
        }
    }

    record JsonString(String value) implements JsonValue {

        public JsonString {
            Objects.requireNonNull(value, "value");
        }
    }

    /** Número com o token lexical exatamente como recebido. */
    record JsonNumber(String lexical) implements JsonValue {

        public JsonNumber {
            Objects.requireNonNull(lexical, "lexical");
        }

        /** Verdadeiro se o token não tem parte fracionária nem expoente. */
        public boolean isIntegerToken() {
            return lexical.indexOf('.') < 0 && lexical.indexOf('e') < 0 && lexical.indexOf('E') < 0;
        }
    }

    record JsonBoolean(boolean value) implements JsonValue {
    }

    record JsonNull() implements JsonValue {
    }
}
