/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Valores normativos fixos da política de assinatura 0.2.0 (IG seguranca SES-GO).
 */
public final class Policy020 {

    /** Identificador (URI versionada) da política — também chave da pipeline no YAML. */
    public static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";

    /** Identificador do algoritmo de canonicalização lossless (C8). */
    public static final String CANONICALIZATION_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/canonicalizacao/fhir-json-lossless/0.2.0";

    /** Máximo de certificados na cadeia (folha + ACs), na assinatura e no {@code x5c}; caminhos ICP-Brasil têm 3 a 4 níveis. */
    public static final int MAX_CHAIN_LENGTH = 10;

    /** OID de <em>Verification Signature</em> (ASTM E1762-95), único propósito admitido. */
    public static final String VERIFICATION_SIGNATURE_OID = "1.2.840.10065.1.12.1.5";

    public static final String SIGNATURE_TYPE_SYSTEM = "urn:iso-astm:E1762-95:2013";
    public static final String SIG_FORMAT = "application/jose+json";
    public static final String TARGET_FORMAT = "application/fhir+json";
    public static final String JWS_ALGORITHM = "RS256";

    /** Faixa admitida para timestamps de referência: 2025-07-01T00:00:00Z a 2100-01-01T00:00:00Z. */
    public static final long MIN_TIMESTAMP = 1751328000L;
    public static final long MAX_TIMESTAMP = 4102444800L;

    /** Tolerância entre relógios de cliente e servidor e entre {@code iat} e o carimbo TSA. */
    public static final long CLOCK_TOLERANCE_SECONDS = 300L;

    /** {@code urn:uuid:} canônico (RFC 4122), inteiramente em minúsculas. */
    public static final Pattern LOWERCASE_UUID_URN = Pattern.compile(
            "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    /**
     * Steps obrigatórios, nesta ordem, do pipeline SIGNING da política (casos de uso de criação);
     * conferidos na partida — o YAML pode acrescentar steps, nunca omitir ou reordenar estes.
     */
    public static final List<String> REQUIRED_SIGNING_STEPS = List.of(
            "context-validation", "payload-validation", "pkix-chain-validation", "certificate-policy",
            "framed-content-digest", "jades-data-to-sign", "crypto-signing", "jades-assemble",
            "jades-extension", "tsa-token-verification", "fhir-signature");

    /** Steps obrigatórios, nesta ordem, do pipeline VALIDATION da política (caso de uso de validação). */
    public static final List<String> REQUIRED_VALIDATION_STEPS = List.of(
            "validation-context", "signature-binding", "jws-structure", "content-integrity",
            "signer-certificate", "dss-validation", "timestamp-validation", "validation-outcome");

    private Policy020() {
    }
}
