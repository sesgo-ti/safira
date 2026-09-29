/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest.Part;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FramedContentDigestTest {

    private static Part part(String target, String resource) {
        return new Part(target, resource.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldFrameWithUint64BigEndianLengths() throws Exception {
        byte[] framed = FramedContentDigest.frame(List.of(part("urn:uuid:a", "{}")));

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 1});
        expected.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 10});
        expected.write("urn:uuid:a".getBytes(StandardCharsets.US_ASCII));
        expected.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 2});
        expected.write("{}".getBytes(StandardCharsets.US_ASCII));
        assertThat(framed).isEqualTo(expected.toByteArray());
    }

    @Test
    void shouldMeasureLengthsInOctets() {
        byte[] framed = FramedContentDigest.frame(List.of(part("t", "é")));

        // N(8) + len(T)(8) + "t"(1) + len(R)(8) + "é"(2 octetos)
        assertThat(framed).hasSize(27);
        assertThat(framed[25 - 8]).isEqualTo((byte) 0);
        assertThat(framed[24]).isEqualTo((byte) 2);
    }

    @Test
    void shouldRejectEmptyParts() {
        assertThatThrownBy(() -> FramedContentDigest.frame(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldProduceSha256OfFramedArtifact() throws Exception {
        List<Part> parts = List.of(part("urn:uuid:a", "{\"x\":1}"), part("urn:uuid:b", "{}"));

        byte[] digest = FramedContentDigest.sha256(parts);

        assertThat(digest).hasSize(32)
                .isEqualTo(MessageDigest.getInstance("SHA-256").digest(FramedContentDigest.frame(parts)));
    }

    @Test
    void shouldDistinguishBoundaryShifts() {
        byte[] a = FramedContentDigest.sha256(List.of(part("ab", "c")));
        byte[] b = FramedContentDigest.sha256(List.of(part("a", "bc")));

        assertThat(a).isNotEqualTo(b);
    }
}
