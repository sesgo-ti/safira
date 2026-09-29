/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;

/**
 * Artefato enquadrado da política 0.2.0 (C8):
 * {@code UINT64_BE(N) || UINT64_BE(len(T1)) || T1 || UINT64_BE(len(R1)) || R1 || ...},
 * em que {@code Ti} é o texto de {@code Provenance.target[i].reference} e {@code Ri} o recurso
 * canonicalizado correspondente. O SHA-256 desse artefato é o payload attached do JWS.
 */
public final class FramedContentDigest {

    /**
     * @param target            valor exato de {@code Provenance.target[i].reference}
     * @param canonicalResource bytes UTF-8 da canonicalização lossless do recurso
     */
    public record Part(String target, byte[] canonicalResource) {

        public Part {
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(canonicalResource, "canonicalResource");
        }
    }

    private FramedContentDigest() {
    }

    public static byte[] frame(List<Part> parts) {
        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException("O artefato enquadrado exige ao menos um par target/recurso");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeUint64(out, parts.size());
        for (Part part : parts) {
            byte[] target = part.target().getBytes(StandardCharsets.UTF_8);
            writeUint64(out, target.length);
            out.writeBytes(target);
            writeUint64(out, part.canonicalResource().length);
            out.writeBytes(part.canonicalResource());
        }
        return out.toByteArray();
    }

    public static byte[] sha256(List<Part> parts) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(frame(parts));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível na JVM", e);
        }
    }

    private static void writeUint64(ByteArrayOutputStream out, long value) {
        out.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
    }
}
