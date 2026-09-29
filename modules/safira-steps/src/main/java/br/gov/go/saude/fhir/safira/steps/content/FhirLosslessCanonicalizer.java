/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonBoolean;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNull;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNumber;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.TreeSet;

/**
 * Canonicalização {@code fhir-json-lossless/0.2.0} de um recurso FHIR selecionado (política C8).
 *
 * <p>Remove, somente no objeto raiz, {@code id}/{@code _id} e, em {@code meta},
 * {@code versionId}, {@code lastUpdated}, {@code source}, {@code tag} (e seus acompanhantes
 * {@code _}); omite {@code meta} se ficar vazio. Serializa ordenando membros por unidades de
 * código UTF-16, sem whitespace, strings com escaping RFC 8785 e números com o token lexical
 * original. Resultado em UTF-8 sem BOM.
 */
public final class FhirLosslessCanonicalizer {

    public static final String URI = Policy020.CANONICALIZATION_URI;

    private static final String[] ROOT_REMOVALS = {"id", "_id"};
    private static final String[] META_REMOVALS = {
            "versionId", "_versionId", "lastUpdated", "_lastUpdated", "source", "_source", "tag"};

    private FhirLosslessCanonicalizer() {
    }

    public static byte[] canonicalize(JsonObject resource) {
        JsonObject stripped = resource.without(ROOT_REMOVALS);
        Optional<JsonObject> meta = stripped.object("meta");
        if (meta.isPresent()) {
            JsonObject remaining = meta.get().without(META_REMOVALS);
            stripped = remaining.members().isEmpty()
                    ? stripped.without("meta")
                    : stripped.with("meta", remaining);
        }
        StringBuilder out = new StringBuilder();
        writeCanonical(out, stripped);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void writeCanonical(StringBuilder out, JsonValue value) {
        switch (value) {
            case JsonObject object -> {
                out.append('{');
                boolean first = true;
                // String#compareTo compara unidades de código UTF-16, como exige C8
                for (String name : new TreeSet<>(object.names())) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    LosslessJson.appendEscaped(out, name);
                    out.append(':');
                    writeCanonical(out, object.members().get(name));
                }
                out.append('}');
            }
            case JsonArray array -> {
                out.append('[');
                for (int i = 0; i < array.items().size(); i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    writeCanonical(out, array.items().get(i));
                }
                out.append(']');
            }
            case JsonString string -> LosslessJson.appendEscaped(out, string.value());
            // DIVERGENCIA-IG D5: token preservado para todo número, sem distinguir integer/decimal pelo esquema FHIR
            case JsonNumber number -> out.append(number.lexical());
            case JsonBoolean bool -> out.append(bool.value());
            case JsonNull ignored -> out.append("null");
        }
    }
}
