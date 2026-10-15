/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.simulador;

import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;

import java.security.cert.X509Certificate;

/**
 * Substitui a consulta real de OCSP/CRL por uma resposta OCSP {@code GOOD} sempre válida,
 * assinada pela {@link SimuladorPki}. Ativo só com o profile {@code simulado}.
 */
final class SimuladorRevocationService extends RevocationService {

    private final SimuladorPki pki;

    SimuladorRevocationService(SimuladorPki pki) {
        super(null, null);
        this.pki = pki;
    }

    @Override
    public RevocationLookup lookup(X509Certificate cert, X509Certificate issuer) {
        byte[] der = pki.ocspGoodFor(cert);
        return new RevocationLookup(new RevocationStatus.Good("simulador", der), new RevocationEvidence.OcspResponse(der));
    }
}
