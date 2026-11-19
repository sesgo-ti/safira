/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class FramedContentDigestStepTest {

    private static final String U1 = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6";
    private static final String U2 = "urn:uuid:9b2b8c1e-2f4a-4d5b-8c6d-7e8f9a0b1c2d";
    private static final String BUNDLE = "{\"resourceType\":\"Bundle\",\"entry\":["
            + "{\"fullUrl\":\"" + U1 + "\",\"resource\":{\"resourceType\":\"Patient\",\"id\":\"a\",\"meta\":{\"versionId\":\"1\"}}},"
            + "{\"fullUrl\":\"" + U2 + "\",\"resource\":{\"resourceType\":\"Observation\",\"valueQuantity\":{\"value\":2.00}}}]}";

    private static String digest(String bundle, String... targets) {
        StringBuilder refs = new StringBuilder();
        for (String target : targets) {
            refs.append(refs.isEmpty() ? "" : ",").append("{\"reference\":\"").append(target).append("\"}");
        }
        SigningContext context = SigningContext.builder()
                .bundleJson(LosslessJson.parseObject(bundle))
                .provenanceJson(LosslessJson.parseObject("{\"resourceType\":\"Provenance\",\"target\":[" + refs + "]}"))
                .build();
        StepResult<SigningContext> result = new FramedContentDigestStep().execute(context);
        return result.context().getAttribute(SigningKeys.CONTENT_DIGEST, String.class).orElseThrow();
    }

    @Test
    void shouldProduce43CharBase64UrlDigest() {
        assertThat(digest(BUNDLE, U1, U2)).hasSize(43).matches("^[A-Za-z0-9_-]{43}$");
    }

    @Test
    void shouldMatchKnownFramedArtifact() throws Exception {
        byte[] t = U1.getBytes(StandardCharsets.UTF_8);
        byte[] r = "{\"resourceType\":\"Patient\"}".getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(new byte[]{0, 0, 0, 0, 0, 0, 0, 1});
        sha.update(new byte[]{0, 0, 0, 0, 0, 0, 0, (byte) t.length});
        sha.update(t);
        sha.update(new byte[]{0, 0, 0, 0, 0, 0, 0, (byte) r.length});
        sha.update(r);

        assertThat(digest(BUNDLE, U1)).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(sha.digest()));
    }

    @Test
    void shouldChangeDigestWhenTargetOrderChanges() {
        assertThat(digest(BUNDLE, U1, U2)).isNotEqualTo(digest(BUNDLE, U2, U1));
    }

    @Test
    void shouldChangeDigestWhenDecimalLexicalChanges() {
        assertThat(digest(BUNDLE, U2)).isNotEqualTo(digest(BUNDLE.replace("2.00", "2.0"), U2));
    }

    @Test
    void shouldIgnoreRootMetaVersionId() {
        assertThat(digest(BUNDLE, U1)).isEqualTo(digest(BUNDLE.replace("\"versionId\":\"1\"", "\"versionId\":\"2\""), U1));
    }
}
