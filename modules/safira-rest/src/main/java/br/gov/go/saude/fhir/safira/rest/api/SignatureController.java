/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.api;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.rest.service.ValidationService;
import br.gov.go.saude.fhir.safira.rest.service.VersionsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureController {

    private static final MediaType FHIR_JSON = MediaType.parseMediaType("application/fhir+json");

    private final VersionsService versionsService;
    private final SigningService signingService;
    private final ValidationService validationService;

    public SignatureController(VersionsService versionsService,
                               SigningService signingService,
                               ValidationService validationService) {
        this.versionsService = versionsService;
        this.signingService = signingService;
        this.validationService = validationService;
    }

    /**
     * Cria a assinatura (política 0.2.0). O corpo é lido cru para preservar os tokens lexicais
     * dos elementos FHIR {@code decimal}, exigência da canonicalização lossless.
     *
     * @return 200 com {@code {"signature": Signature, "provenance": Provenance}} ou 422 com
     * {@code OperationOutcome}
     */
    @PostMapping("/assinar")
    public ResponseEntity<?> sign(@RequestBody String body) {
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
     * @return 200 com {@code OperationOutcome} {@code VALIDATION.SUCCESS} ou 422 com o código da rejeição
     */
    @PostMapping("/validar")
    public ResponseEntity<?> validate(@RequestBody String body) {
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

    @GetMapping("/versoes")
    public ResponseEntity<String> versionsSupported() {
        return ResponseEntity
                .ok()
                .contentType(FHIR_JSON)
                .body(versionsService.getVersionsSupported().toString());
    }
}
