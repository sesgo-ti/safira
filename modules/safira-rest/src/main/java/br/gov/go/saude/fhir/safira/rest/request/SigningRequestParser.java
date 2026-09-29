/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Converte o corpo JSON de {@code POST /assinar} em {@link SigningContext} sem perda.
 *
 * <p>O corpo é lido pelo parser lossless: Bundle e Provenance mantêm os tokens numéricos
 * originais e membros duplicados são rejeitados, como exige a canonicalização da política
 * 0.2.0. Regras de conteúdo e de política ficam nos steps da pipeline, que devolvem os
 * códigos do IG; aqui só se rejeita o que impede montar o contexto.
 *
 * <p>Campos: {@code bundle}, {@code provenance}, {@code signerCryptoMaterial}
 * ({@code type} PEM ou PKCS12), {@code certificateChain}, {@code referenceTimestamp},
 * {@code strategy} ({@code iat}|{@code tsa}) e {@code policyIdentifierUri}.
 */
public final class SigningRequestParser {

    private SigningRequestParser() {
    }

    public static SigningContext parse(String body, SafiraOperationalConfigProperties operationalConfig) {
        JsonObject root = RequestFields.root(body);
        return SigningContext.builder()
                .bundleJson(RequestFields.object(root, "bundle", SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED))
                .provenanceJson(RequestFields.object(root, "provenance", SignatureExceptionCode.FORMAT_PROVENANCE_INVALID))
                .cryptoMaterial(cryptoMaterial(root))
                .rawCertificateChain(certificateChain(root))
                .referenceTimestamp(RequestFields.timestamp(root, "referenceTimestamp"))
                .strategy(strategy(root.string("strategy").orElse(null)))
                .policyIdentifierUri(root.string("policyIdentifierUri").orElse(null))
                .operationalConfig(operationalConfig)
                .build();
    }

    private static TimestampStrategy strategy(String value) {
        if ("iat".equals(value)) {
            return TimestampStrategy.IAT;
        }
        if ("tsa".equals(value)) {
            return TimestampStrategy.TSA;
        }
        return null;
    }

    private static List<String> certificateChain(JsonObject root) {
        List<String> chain = new ArrayList<>();
        root.array("certificateChain").ifPresent(array -> {
            for (JsonValue item : array.items()) {
                if (!(item instanceof JsonString string)) {
                    throw new RequestParsingException(SignatureExceptionCode.FORMAT_BASE64_INVALID,
                            "Cada item de 'certificateChain' deve ser uma string Base64 com um certificado DER.");
                }
                chain.add(string.value());
            }
        });
        return List.copyOf(chain);
    }

    private static CryptoMaterial cryptoMaterial(JsonObject root) {
        JsonObject material = RequestFields.object(root, "signerCryptoMaterial", SignatureExceptionCode.CONFIG_MISSING_PARAMETER);
        String type = material.string("type").orElse("");
        return switch (type) {
            case "PEM" -> new CryptoMaterial.PemMaterial(
                    material.string("privateKeyBase64").orElse(null),
                    material.string("password").orElse(null));
            case "PKCS12" -> new CryptoMaterial.Pkcs12Material(
                    material.string("contentBase64").orElse(null),
                    material.string("password").orElse(null),
                    material.string("alias").orElse(null));
            // DIVERGENCIA-IG D13: SMARTCARD/TOKEN (PKCS#11) e REMOTE previstos no IG, fora do escopo desta versão
            default -> throw new RequestParsingException(SignatureExceptionCode.CONFIG_INVALID_PARAMETER,
                    "Tipo de material criptográfico não suportado: '" + type + "' (suportados: PEM, PKCS12).");
        };
    }
}
