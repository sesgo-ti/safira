package br.gov.go.saude.fhir.safira.api;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignatureController {

    @PostMapping("/assinar")
    public ResponseEntity<String> assinar() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("Objeto assinado com sucesso!");
    }


    @PostMapping("/verificar")
    public ResponseEntity<String> verificar() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("Objeto teve assinatura verificada com sucesso!");
    }

    @GetMapping("/versoes")
    public ResponseEntity<String> versoes() {
        return ResponseEntity
                .ok()
                .contentType(MediaType.parseMediaType("application/fhir+json"))
                .body("https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0");
    }
}
