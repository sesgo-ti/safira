/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.revocation;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.steps.certificate.PkixResults;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;

import java.security.cert.CRLException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Coleta, pela lib icpbrasil-truststore, as respostas OCSP e CRLs completas que fundamentam o
 * estado de revogação de cada certificado não raiz das cadeias informadas (validar 6.1).
 *
 * <p>A lib aplica sua política de download (SSRF, limites de tamanho) e valida cada resposta; as
 * evidências verificadas alimentam o EU DSS, que nunca acessa a rede por conta própria.
 * Resultado inconclusivo nunca vira sucesso.
 */
public final class LibRevocationEvidence {

    /**
     * @param ocspResponses respostas OCSP completas (DER de {@code OCSPResponse})
     * @param crls          CRLs completas (DER)
     * @param revoked       certificados com veredicto {@code Revoked}
     */
    public record Collected(List<byte[]> ocspResponses, List<byte[]> crls, List<X509Certificate> revoked) {
    }

    public sealed interface Outcome {

        record Ok(Collected collected) implements Outcome {
        }

        record Failed(SignatureExceptionCode code, String diagnostics) implements Outcome {
        }
    }

    private LibRevocationEvidence() {
    }

    /**
     * @param chains cadeias ordenadas da folha para a raiz; o último elemento de cada uma é a âncora
     */
    public static Outcome collect(RevocationService revocationService, List<List<X509Certificate>> chains) {
        List<byte[]> ocsp = new ArrayList<>();
        List<byte[]> crls = new ArrayList<>();
        List<X509Certificate> revoked = new ArrayList<>();
        for (List<X509Certificate> chain : chains) {
            for (int i = 0; i < chain.size() - 1; i++) {
                X509Certificate certificate = chain.get(i);
                RevocationLookup lookup = revocationService.lookup(certificate, chain.get(i + 1));
                if (!lookup.isConclusive()) {
                    return new Outcome.Failed(PkixResults.revocationCode(lookup.status()),
                            "Estado de revogação inconclusivo para " + certificate.getSubjectX500Principal().getName()
                                    + ": " + lookup.status().getClass().getSimpleName() + ".");
                }
                if (lookup.status() instanceof RevocationStatus.Revoked) {
                    revoked.add(certificate);
                }
                switch (lookup.evidence()) {
                    case RevocationEvidence.OcspResponse response -> ocsp.add(response.der());
                    case RevocationEvidence.Crl crl -> crls.add(encoded(crl));
                }
            }
        }
        return new Outcome.Ok(new Collected(List.copyOf(ocsp), List.copyOf(crls), List.copyOf(revoked)));
    }

    private static byte[] encoded(RevocationEvidence.Crl crl) {
        try {
            return crl.crl().getEncoded();
        } catch (CRLException e) {
            throw new IllegalStateException("CRL verificada pela lib não pôde ser recodificada", e);
        }
    }
}
