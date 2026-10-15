/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * {@code GET /simulacao/pki}: só o material PÚBLICO da PKI simulada persistida — raiz, AC e cadeia do
 * signatário em PEM, o diretório e os valores da allowlist. Chaves, PKCS#12 e senha nunca saem por aqui:
 * a resposta é montada uma vez, só a partir de certificados.
 */
@RestController
public class PkiPublicaController {

    /**
     * Material público da PKI simulada.
     *
     * @param diretorio        diretório da PKI (os PKCS#12 e a {@code senha.txt} ficam nele)
     * @param raiz             certificado da raiz (âncora) em PEM
     * @param ac               certificado da AC emissora em PEM
     * @param cadeiaSignatario cadeia do signatário em PEM: folha, AC, raiz
     * @param issuerSha256     SHA-256 do DER da AC (allowlist)
     * @param politicaOid      OID de política A3 do signatário (allowlist)
     */
    public record PkiPublica(String diretorio, String raiz, String ac, List<String> cadeiaSignatario,
                             String issuerSha256, String politicaOid) {
    }

    private final PkiPublica publica;

    public PkiPublicaController(PkiPersistida pki) {
        this.publica = new PkiPublica(pki.diretorio().toString(), pem(pki.pki().raiz()), pem(pki.pki().ac()),
                pki.pki().cadeia().stream().map(PkiPublicaController::pem).toList(), pki.issuerSha256(),
                pki.politicaOid());
    }

    @GetMapping(path = "/simulacao/pki", produces = MediaType.APPLICATION_JSON_VALUE)
    public PkiPublica pki() {
        return publica;
    }

    private static String pem(X509Certificate certificado) {
        try {
            return GeradorPkiSimulada.pem(certificado);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Certificado da PKI simulada ilegível", e);
        }
    }
}
