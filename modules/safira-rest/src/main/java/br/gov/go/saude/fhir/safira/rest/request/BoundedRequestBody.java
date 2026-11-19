/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import jakarta.servlet.http.HttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Lê o corpo cru de {@code /assinar} e {@code /validar} com limite de bytes, antes de qualquer parse.
 *
 * <p>O limite é {@code safira.operational.security.max-bundle-size} mais uma folga fixa para os
 * demais membros da requisição (Provenance, Signature, cadeia, material criptográfico). O
 * {@code Content-Length} declarado é recusado de imediato; sem ele, a leitura para ao exceder.
 */
public final class BoundedRequestBody {

    /** Folga sobre o tamanho máximo do Bundle para os demais membros da requisição. */
    public static final long OVERHEAD_BYTES = 4L * 1024 * 1024;

    private static final long DEFAULT_MAX_BUNDLE_SIZE = 52_428_800L;
    private static final int BUFFER_SIZE = 8192;

    private BoundedRequestBody() {
    }

    /** Limite em bytes do corpo da requisição derivado da configuração operacional. */
    public static long limit(SafiraOperationalConfigProperties config) {
        Integer maxBundleSize = config == null || config.security() == null ? null : config.security().maxBundleSize();
        return (maxBundleSize != null ? maxBundleSize : DEFAULT_MAX_BUNDLE_SIZE) + OVERHEAD_BYTES;
    }

    /**
     * @throws RequestParsingException com {@code SECURITY.BUNDLE-SIZE-LIMIT-EXCEEDED} se o corpo exceder o limite
     */
    public static String read(HttpServletRequest request, long limit) throws IOException {
        if (request.getContentLengthLong() > limit) {
            throw tooLarge(limit);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = request.getInputStream()) {
            for (int read = in.read(buffer); read != -1; read = in.read(buffer)) {
                if (out.size() + (long) read > limit) {
                    throw tooLarge(limit);
                }
                out.write(buffer, 0, read);
            }
        }
        Charset charset = request.getCharacterEncoding() != null
                ? Charset.forName(request.getCharacterEncoding()) : StandardCharsets.UTF_8;
        return out.toString(charset);
    }

    private static RequestParsingException tooLarge(long limit) {
        return new RequestParsingException(SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED,
                "O corpo da requisição excede o limite de " + limit + " bytes.");
    }
}
