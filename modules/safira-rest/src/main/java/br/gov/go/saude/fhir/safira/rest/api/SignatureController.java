package br.gov.go.saude.fhir.safira.rest.api;

import br.gov.go.saude.fhir.safira.rest.service.VersionsService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureController {
    public final VersionsService versionsService;

    public SignatureController(VersionsService versionsService) {
        this.versionsService = versionsService;
    }

    @PostMapping("/assinar")
    public ResponseEntity<String> sign() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("Objeto assinado com sucesso!");
    }


    @PostMapping("/verificar")
    public ResponseEntity<String> verify() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("Objeto teve assinatura verificada com sucesso!");
    }

    @GetMapping("/versoes")
    public ResponseEntity<String> versionsSupported() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body(versionsService.getVersionsSupported().toString());
    }
}
