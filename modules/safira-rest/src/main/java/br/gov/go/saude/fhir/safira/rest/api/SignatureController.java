/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.api;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.rest.request.BoundedRequestBody;
import br.gov.go.saude.fhir.safira.rest.request.RequestParsingException;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.rest.service.ValidationService;
import br.gov.go.saude.fhir.safira.rest.service.VersionsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

@RestController
public class SignatureController {

    private static final MediaType FHIR_JSON = MediaType.parseMediaType("application/fhir+json");

    private final VersionsService versionsService;
    private final SigningService signingService;
    private final ValidationService validationService;
    private final long maxRequestBytes;

    public SignatureController(VersionsService versionsService,
                               SigningService signingService,
                               ValidationService validationService,
                               SafiraOperationalConfigProperties operationalConfig) {
        this.versionsService = versionsService;
        this.signingService = signingService;
        this.validationService = validationService;
        this.maxRequestBytes = BoundedRequestBody.limit(operationalConfig);
    }

    /**
     * Cria a assinatura (política 0.2.0). O corpo é lido cru para preservar os tokens lexicais
     * dos elementos FHIR {@code decimal}, exigência da canonicalização lossless.
     *
     * @return 200 com {@code {"signature": Signature, "provenance": Provenance}}, 413 se o corpo
     * exceder o limite de segurança ou 422 com {@code OperationOutcome}
     */
    @PostMapping("/assinar")
    public ResponseEntity<?> sign(HttpServletRequest request) throws IOException {
        String body;
        try {
            body = BoundedRequestBody.read(request, maxRequestBytes);
        } catch (RequestParsingException e) {
            return tooLarge(e);
        }
        PipelineResult<?> result = signingService.sign(body);

        return switch (result) {
            // DIVERGENCIA-IG D12: o IG não define o envelope da resposta que devolve Signature e Provenance
            case PipelineResult.Success<?> success when success.getValue() instanceof SigningResult signed -> ResponseEntity
                    .status(HttpStatus.OK)
                    .contentType(FHIR_JSON)
                    .body("{\"signature\":" + signed.signatureJson() + ",\"provenance\":" + signed.provenanceJson() + "}");
            case PipelineResult.Success<?> success -> ResponseEntity
                    .status(HttpStatus.OK)
                    .contentType(FHIR_JSON)
                    .body(success.getValue());
            case PipelineResult.Failure<?> failure -> ResponseEntity
                    .status(HttpStatus.UNPROCESSABLE_ENTITY)
                    .contentType(FHIR_JSON)
                    .body(failure.getExceptionDetails());
        };
    }

    /**
     * Valida a assinatura (política 0.2.0) a partir de {@code signature}, {@code bundle} e
     * {@code provenance} lidos sem perda.
     *
     * @return 200 com {@code OperationOutcome} {@code VALIDATION.SUCCESS}, 413 se o corpo exceder o
     * limite de segurança ou 422 com o código da rejeição
     */
    @PostMapping("/validar")
    public ResponseEntity<?> validate(HttpServletRequest request) throws IOException {
        String body;
        try {
            body = BoundedRequestBody.read(request, maxRequestBytes);
        } catch (RequestParsingException e) {
            return tooLarge(e);
        }
        PipelineResult<OperationOutcome> result = validationService.validate(body);

        return switch (result) {
            case PipelineResult.Success<OperationOutcome> success -> ResponseEntity
                    .status(HttpStatus.OK)
                    .contentType(FHIR_JSON)
                    .body(success.getValue());
            case PipelineResult.Failure<OperationOutcome> failure -> ResponseEntity
                    .status(HttpStatus.UNPROCESSABLE_ENTITY)
                    .contentType(FHIR_JSON)
                    .body(failure.getExceptionDetails());
        };
    }

    private static ResponseEntity<OperationOutcome> tooLarge(RequestParsingException e) {
        return ResponseEntity
                .status(HttpStatus.CONTENT_TOO_LARGE)
                .contentType(FHIR_JSON)
                .body(OperationOutcome.createSignatureError(e.getCode().getSeverity(), "too-costly",
                        e.getCode().getCode(), e.getCode().getDisplay(), e.getMessage()));
    }

    /** URIs das políticas suportadas: array JSON de strings, em ordem (não é recurso FHIR). */
    @GetMapping("/versoes")
    public ResponseEntity<List<String>> versionsSupported() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(versionsService.getVersionsSupported().stream().sorted().toList());
    }
}
