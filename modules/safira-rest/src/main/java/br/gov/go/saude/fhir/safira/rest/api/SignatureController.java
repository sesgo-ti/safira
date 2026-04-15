package br.gov.go.saude.fhir.safira.rest.api;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInputValidator;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.rest.service.VersionsService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureController {
    private final VersionsService versionsService;
    private final SigningService signingService;
    private final SigningInputValidator signingInputValidator;

    public SignatureController(VersionsService versionsService, SigningService signingService, SigningInputValidator signingInputValidator) {
        this.versionsService = versionsService;
        this.signingService = signingService;
        this.signingInputValidator = signingInputValidator;
    }

    @InitBinder("input")
    protected void initBinder(WebDataBinder binder) {
        binder.addValidators(signingInputValidator);
    }

    @PostMapping("/assinar")
    public ResponseEntity<?> sign(@Valid @RequestBody SigningInput input) {
        PipelineResult<?> result = signingService.sign(input);
        
        return switch (result) {
            case PipelineResult.Success<?> success -> ResponseEntity
                    .status(HttpStatus.OK)
                    .contentType(MediaType.parseMediaType("application/fhir+json"))
                    .body(success.getValue());
            case PipelineResult.Failure<?> failure -> ResponseEntity
                    .status(HttpStatus.UNPROCESSABLE_ENTITY)
                    .contentType(MediaType.parseMediaType("application/fhir+json"))
                    .body(failure.getExceptionDetails());
        };
    }

    @PostMapping("/validar")
    public ResponseEntity<String> validate() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("Objeto teve assinatura validada com sucesso!");
    }

    @GetMapping("/versoes")
    public ResponseEntity<String> versionsSupported() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body(versionsService.getVersionsSupported().toString());
    }
}
