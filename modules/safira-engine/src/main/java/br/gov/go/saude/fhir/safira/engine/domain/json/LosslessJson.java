/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.json;

import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonBoolean;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNull;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNumber;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser e serializador JSON sem perda.
 *
 * <p>O parse é estrito: rejeita membros duplicados em qualquer objeto, conteúdo após o valor
 * raiz e surrogates UTF-16 isolados. Números mantêm o token lexical original. A escrita é
 * compacta, preserva a ordem dos membros e escapa strings conforme a RFC 8785 §3.2.2.2.
 */
public final class LosslessJson {

    private static final JsonFactory FACTORY = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private LosslessJson() {
    }

    public static JsonValue parse(String json) {
        if (json == null) {
            throw new LosslessJsonException("JSON ausente");
        }
        try (JsonParser parser = FACTORY.createParser(json)) {
            JsonToken first = parser.nextToken();
            if (first == null) {
                throw new LosslessJsonException("JSON vazio");
            }
            JsonValue value = read(parser, first);
            if (parser.nextToken() != null) {
                throw new LosslessJsonException("Conteúdo após o valor JSON raiz");
            }
            return value;
        } catch (IOException e) {
            throw new LosslessJsonException("JSON inválido: " + e.getMessage(), e);
        }
    }

    public static JsonObject parseObject(String json) {
        if (parse(json) instanceof JsonObject object) {
            return object;
        }
        throw new LosslessJsonException("O valor JSON raiz deve ser um objeto");
    }

    public static String write(JsonValue value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    /** Escreve a string entre aspas com o escaping da RFC 8785 §3.2.2.2. */
    public static void appendEscaped(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append("\\u00").append(HEX[c >> 4]).append(HEX[c & 0xF]);
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static void write(StringBuilder out, JsonValue value) {
        switch (value) {
            case JsonObject object -> {
                out.append('{');
                boolean first = true;
                for (Map.Entry<String, JsonValue> member : object.members().entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    appendEscaped(out, member.getKey());
                    out.append(':');
                    write(out, member.getValue());
                }
                out.append('}');
            }
            case JsonArray array -> {
                out.append('[');
                for (int i = 0; i < array.items().size(); i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    write(out, array.items().get(i));
                }
                out.append(']');
            }
            case JsonString string -> appendEscaped(out, string.value());
            case JsonNumber number -> out.append(number.lexical());
            case JsonBoolean bool -> out.append(bool.value());
            case JsonNull ignored -> out.append("null");
        }
    }

    private static JsonValue read(JsonParser parser, JsonToken token) throws IOException {
        return switch (token) {
            case START_OBJECT -> {
                Map<String, JsonValue> members = new LinkedHashMap<>();
                for (JsonToken next = parser.nextToken(); next != JsonToken.END_OBJECT; next = parser.nextToken()) {
                    String name = checkUnicode(parser.currentName());
                    members.put(name, read(parser, parser.nextToken()));
                }
                yield new JsonObject(members);
            }
            case START_ARRAY -> {
                List<JsonValue> items = new ArrayList<>();
                for (JsonToken next = parser.nextToken(); next != JsonToken.END_ARRAY; next = parser.nextToken()) {
                    items.add(read(parser, next));
                }
                yield new JsonArray(items);
            }
            case VALUE_STRING -> new JsonString(checkUnicode(parser.getText()));
            // getText() devolve o token numérico exatamente como está na entrada
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> new JsonNumber(parser.getText());
            case VALUE_TRUE -> new JsonBoolean(true);
            case VALUE_FALSE -> new JsonBoolean(false);
            case VALUE_NULL -> new JsonNull();
            default -> throw new LosslessJsonException("Token JSON inesperado: " + token);
        };
    }

    private static String checkUnicode(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    throw new LosslessJsonException("Surrogate UTF-16 alto sem par na posição " + i);
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new LosslessJsonException("Surrogate UTF-16 baixo isolado na posição " + i);
            }
        }
        return value;
    }
}
