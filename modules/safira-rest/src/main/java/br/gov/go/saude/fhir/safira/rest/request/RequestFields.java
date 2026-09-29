/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNumber;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJsonException;

import java.util.Optional;

/** Leitura dos campos comuns das requisições de assinatura e validação. */
final class RequestFields {

    private RequestFields() {
    }

    static JsonObject root(String body) {
        try {
            return LosslessJson.parseObject(body);
        } catch (LosslessJsonException e) {
            throw new RequestParsingException(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED,
                    "Requisição não é um objeto JSON válido e sem membros duplicados: " + e.getMessage());
        }
    }

    /** Objeto obrigatório; ausente ou de outro tipo gera o código informado. */
    static JsonObject object(JsonObject root, String name, SignatureExceptionCode code) {
        return root.object(name).orElseThrow(() ->
                new RequestParsingException(code, "O campo '" + name + "' deve ser um objeto JSON."));
    }

    /** NumericDate inteiro (sem fração nem expoente); nulo quando ausente. */
    static Long timestamp(JsonObject root, String name) {
        Optional<JsonValue> value = root.get(name);
        if (value.isEmpty()) {
            return null;
        }
        if (!(value.get() instanceof JsonNumber number) || !number.isIntegerToken()) {
            throw new RequestParsingException(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT,
                    "O campo '" + name + "' deve ser um número inteiro de segundos (NumericDate).");
        }
        try {
            return Long.parseLong(number.lexical());
        } catch (NumberFormatException e) {
            throw new RequestParsingException(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT,
                    "O campo '" + name + "' excede o intervalo de um inteiro de 64 bits.");
        }
    }
}
