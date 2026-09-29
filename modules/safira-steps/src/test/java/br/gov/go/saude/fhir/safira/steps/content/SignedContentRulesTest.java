/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest.Part;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SignedContentRulesTest {

    static final String U1 = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6";
    static final String U2 = "urn:uuid:9b2b8c1e-2f4a-4d5b-8c6d-7e8f9a0b1c2d";
    private static final SecurityLimitsProps LIMITS = new SecurityLimitsProps(100, 1048576, 10, null, null);

    static String bundle(String... entries) {
        return "{\"resourceType\":\"Bundle\",\"type\":\"collection\",\"entry\":[" + String.join(",", entries) + "]}";
    }

    static String entry(String fullUrl, String resource) {
        return "{\"fullUrl\":\"" + fullUrl + "\",\"resource\":" + resource + "}";
    }

    static String provenance(String... targets) {
        StringBuilder refs = new StringBuilder();
        for (String target : targets) {
            if (!refs.isEmpty()) {
                refs.append(',');
            }
            refs.append("{\"reference\":\"").append(target).append("\"}");
        }
        return "{\"resourceType\":\"Provenance\",\"target\":[" + refs + "]}";
    }

    private static final String PATIENT = "{\"resourceType\":\"Patient\",\"id\":\"p\",\"gender\":\"female\"}";

    private static Optional<SignatureExceptionCode> check(String bundle, String provenance) {
        return SignedContentRules.check(LosslessJson.parseObject(bundle), LosslessJson.parseObject(provenance), LIMITS)
                .map(PolicyViolation::code);
    }

    @Test
    void shouldAcceptConformingContent() {
        assertThat(check(bundle(entry(U1, PATIENT)), provenance(U1))).isEmpty();
    }

    @Test
    void shouldRejectEmptyBundle() {
        assertThat(check(bundle(), provenance(U1))).contains(SignatureExceptionCode.FORMAT_BUNDLE_EMPTY);
    }

    @Test
    void shouldRejectNonBundleResource() {
        assertThat(check("{\"resourceType\":\"Patient\"}", provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldRejectUppercaseFullUrl() {
        assertThat(check(bundle(entry(U1.toUpperCase().replace("URN:UUID:", "urn:uuid:"), PATIENT)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldRejectDuplicateFullUrl() {
        assertThat(check(bundle(entry(U1, PATIENT), entry(U1, PATIENT)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_DUPLICATE_FULLURL);
    }

    @Test
    void shouldRejectUppercaseTargetUuid() {
        String upper = "urn:uuid:3FA85F64-5717-4562-B3FC-2C963F66AFA6";

        assertThat(check(bundle(entry(U1, PATIENT)), provenance(upper)))
                .contains(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_INVALID);
    }

    @Test
    void shouldRejectDuplicateTarget() {
        assertThat(check(bundle(entry(U1, PATIENT)), provenance(U1, U1)))
                .contains(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_DUPLICATE);
    }

    @Test
    void shouldRejectEmptyTargets() {
        assertThat(check(bundle(entry(U1, PATIENT)), provenance()))
                .contains(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID);
    }

    @Test
    void shouldRejectTargetWithoutEntry() {
        assertThat(check(bundle(entry(U1, PATIENT)), provenance(U2)))
                .contains(SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING);
    }

    @Test
    void shouldRejectTargetEntryWithoutResource() {
        assertThat(check(bundle("{\"fullUrl\":\"" + U1 + "\"}"), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_BUNDLE_RESOURCE_MISSING);
    }

    @Test
    void shouldRejectResourceWithoutResourceType() {
        assertThat(check(bundle(entry(U1, "{\"id\":\"x\"}")), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldRejectBundleAboveEntryLimit() {
        String[] entries = new String[101];
        for (int i = 0; i < entries.length; i++) {
            entries[i] = entry(String.format("urn:uuid:3fa85f64-5717-4562-b3fc-%012d", i), PATIENT);
        }

        assertThat(check(bundle(entries), provenance(U1)))
                .contains(SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED);
    }

    @Test
    void shouldRejectReferenceWithIdentifierAndReference() {
        String obs = "{\"resourceType\":\"Observation\",\"subject\":{\"reference\":\"" + U2
                + "\",\"identifier\":{\"system\":\"s\",\"value\":\"v\"}}}";

        assertThat(check(bundle(entry(U1, obs), entry(U2, PATIENT)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_REFERENCE_INVALID);
    }

    @Test
    void shouldRejectRelativeLiteralReference() {
        String obs = "{\"resourceType\":\"Observation\",\"subject\":{\"reference\":\"Patient/123\"}}";

        assertThat(check(bundle(entry(U1, obs)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_REFERENCE_INVALID);
    }

    @Test
    void shouldRejectUuidReferenceAbsentFromBundle() {
        String obs = "{\"resourceType\":\"Observation\",\"subject\":{\"reference\":\"" + U2 + "\"}}";

        assertThat(check(bundle(entry(U1, obs)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_REFERENCE_MISSING);
    }

    @Test
    void shouldRejectContainedReferenceWithoutContainedResource() {
        String obs = "{\"resourceType\":\"Observation\",\"subject\":{\"reference\":\"#pat\"}}";

        assertThat(check(bundle(entry(U1, obs)), provenance(U1)))
                .contains(SignatureExceptionCode.FORMAT_REFERENCE_MISSING);
    }

    @Test
    void shouldAcceptContainedAndContainerReferences() {
        String obs = "{\"resourceType\":\"Observation\",\"contained\":[{\"resourceType\":\"Patient\",\"id\":\"pat\","
                + "\"link\":[{\"other\":{\"reference\":\"#\"},\"type\":\"seealso\"}]}],"
                + "\"subject\":{\"reference\":\"#pat\"},"
                + "\"performer\":[{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"52998224725\"}}],"
                + "\"focus\":[{\"reference\":\"" + U2 + "\"}]}";

        assertThat(check(bundle(entry(U1, obs), entry(U2, PATIENT)), provenance(U1))).isEmpty();
    }

    @Test
    void shouldOrderPartsByProvenanceTargets() {
        JsonObject bundle = LosslessJson.parseObject(bundle(entry(U1, PATIENT), entry(U2, "{\"resourceType\":\"Group\"}")));

        List<Part> parts = SignedContentRules.orderedParts(bundle, LosslessJson.parseObject(provenance(U2, U1)));

        assertThat(parts).extracting(Part::target).containsExactly(U2, U1);
        assertThat(new String(parts.get(1).canonicalResource(), StandardCharsets.UTF_8))
                .isEqualTo("{\"gender\":\"female\",\"resourceType\":\"Patient\"}");
    }
}
