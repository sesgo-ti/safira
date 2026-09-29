/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningRequestParserTest {

    private static final SafiraOperationalConfigProperties OPS =
            new SafiraOperationalConfigProperties(null, null, null, null, null);

    private static String body(String bundle, String timestamp, String material) {
        return "{\"bundle\":" + bundle + ","
                + "\"provenance\":{\"resourceType\":\"Provenance\",\"target\":[{\"reference\":\"urn:uuid:x\"}]},"
                + "\"signerCryptoMaterial\":" + material + ","
                + "\"certificateChain\":[\"MIIB\"],"
                + "\"referenceTimestamp\":" + timestamp + ","
                + "\"strategy\":\"iat\","
                + "\"policyIdentifierUri\":\"https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0\"}";
    }

    private static final String BUNDLE = "{\"resourceType\":\"Bundle\",\"entry\":[{\"fullUrl\":\"urn:uuid:x\","
            + "\"resource\":{\"resourceType\":\"Observation\",\"valueQuantity\":{\"value\":2.00}}}]}";
    private static final String PEM = "{\"type\":\"PEM\",\"privateKeyBase64\":\"cGVt\"}";

    private static SignatureExceptionCode codeOf(Runnable action) {
        try {
            action.run();
        } catch (RequestParsingException e) {
            return e.getCode();
        }
        throw new AssertionError("RequestParsingException esperada");
    }

    @Test
    void shouldKeepDecimalTokenOfBundleResource() {
        SigningContext context = SigningRequestParser.parse(body(BUNDLE, "1790000000", PEM), OPS);

        assertThat(LosslessJson.write(context.getBundleJson())).isEqualTo(BUNDLE);
    }

    @Test
    void shouldMapScalarFields() {
        SigningContext context = SigningRequestParser.parse(body(BUNDLE, "1790000000", PEM), OPS);

        assertThat(context.getReferenceTimestamp()).isEqualTo(1790000000L);
        assertThat(context.getStrategy()).isEqualTo(TimestampStrategy.IAT);
        assertThat(context.getRawCertificateChain()).isEqualTo(List.of("MIIB"));
        assertThat(context.getCryptoMaterial()).isEqualTo(new CryptoMaterial.PemMaterial("cGVt", null));
        assertThat(context.getOperationalConfig()).isSameAs(OPS);
    }

    @Test
    void shouldMapPkcs12Material() {
        String p12 = "{\"type\":\"PKCS12\",\"contentBase64\":\"AA==\",\"password\":\"s\",\"alias\":\"a\"}";

        SigningContext context = SigningRequestParser.parse(body(BUNDLE, "1790000000", p12), OPS);

        assertThat(context.getCryptoMaterial()).isEqualTo(new CryptoMaterial.Pkcs12Material("AA==", "s", "a"));
    }

    @Test
    void shouldRejectDuplicateMemberInRequest() {
        String duplicated = BUNDLE.replace("\"resourceType\":\"Bundle\"", "\"resourceType\":\"Bundle\",\"resourceType\":\"Bundle\"");

        assertThat(codeOf(() -> SigningRequestParser.parse(body(duplicated, "1790000000", PEM), OPS)))
                .isEqualTo(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldRejectFractionalReferenceTimestamp() {
        assertThat(codeOf(() -> SigningRequestParser.parse(body(BUNDLE, "1790000000.5", PEM), OPS)))
                .isEqualTo(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT);
    }

    @Test
    void shouldRejectStringReferenceTimestamp() {
        assertThat(codeOf(() -> SigningRequestParser.parse(body(BUNDLE, "\"1790000000\"", PEM), OPS)))
                .isEqualTo(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT);
    }

    @Test
    void shouldRejectUnsupportedCryptoMaterialType() {
        String token = "{\"type\":\"TOKEN\",\"pin\":\"1234\",\"identifier\":\"k\"}";

        assertThat(codeOf(() -> SigningRequestParser.parse(body(BUNDLE, "1790000000", token), OPS)))
                .isEqualTo(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectBundleThatIsNotObject() {
        assertThat(codeOf(() -> SigningRequestParser.parse(body("[]", "1790000000", PEM), OPS)))
                .isEqualTo(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldLeaveUnknownStrategyForContextValidation() {
        SigningContext context = SigningRequestParser.parse(body(BUNDLE, "1790000000", PEM)
                .replace("\"iat\"", "\"ltv\""), OPS);

        assertThat(context.getStrategy()).isNull();
    }

    @Test
    void shouldRejectInvalidJson() {
        assertThatThrownBy(() -> SigningRequestParser.parse("{", OPS)).isInstanceOf(RequestParsingException.class);
    }
}
