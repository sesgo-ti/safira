/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.timestamp;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;

import java.util.Optional;

/**
 * Apoio comum à verificação do carimbo: política TSA configurada para o token e texto carimbado.
 * A cadeia da TSA e sua revogação são decididas pelo EU DSS ({@code DssOutcomes}).
 */
public final class TsaChainVerification {

    private TsaChainVerification() {
    }

    /** Política TSA configurada cujo OID é exatamente {@code TSTInfo.policy}. */
    public static Optional<TsaPolicy> selectPolicy(SafiraPolicyProperties policy, Inspection inspection) {
        return policy.tsaPolicyList().stream()
                .filter(p -> p.oid().equals(inspection.policyOid()))
                .findFirst();
    }

    /** Texto exato de {@code signatures[0].signature} (base do message imprint). */
    public static String signatureText(String jwsJson) {
        return LosslessJson.parseObject(jwsJson).array("signatures")
                .filter(a -> !a.items().isEmpty())
                .map(a -> a.items().getFirst())
                .filter(JsonObject.class::isInstance)
                .map(JsonObject.class::cast)
                .flatMap(s -> s.string("signature"))
                .orElseThrow(() -> new TimestampTokenException(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                        "JWS sem signatures[0].signature."));
    }
}
