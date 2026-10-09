/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Date;

/**
 * {@link PKITSPSource} da TSA simulada. Acrescenta ao original a accuracy opcional do TSTInfo e a
 * resposta a uma requisição RFC 3161 recebida (nonce e reqPolicy preservados) para o stub HTTP.
 */
final class TsaSimulada extends PKITSPSource {

    private final transient CertEntity tsa;
    private final String politica;
    private final Integer accuracySegundos;

    TsaSimulada(CertEntity tsa, String politica, Date genTime, Integer accuracySegundos) {
        super(tsa);
        this.tsa = tsa;
        this.politica = politica;
        this.accuracySegundos = accuracySegundos;
        setTsaPolicy(politica);
        setProductionTime(genTime);
    }

    /** Resposta RFC 3161 (DER de {@code TimeStampResp}) à requisição recebida. */
    byte[] responder(byte[] requisicaoDer) {
        try {
            TimeStampRequest requisicao = new TimeStampRequest(requisicaoDer);
            DigestAlgorithm digest = DigestAlgorithm.forOID(requisicao.getMessageImprintAlgOID().getId());
            return generateResponse(requisicao, digest).getEncoded();
        } catch (Exception e) {
            throw new DSSException("Falha ao responder a requisição de carimbo simulada", e);
        }
    }

    @Override
    protected TimeStampResponseGenerator initResponseGenerator(DigestAlgorithm digestAlgorithm, Date genTime) {
        if (accuracySegundos == null) {
            return super.initResponseGenerator(digestAlgorithm, genTime);
        }
        try {
            ContentSigner assinador = new JcaContentSignerBuilder(getSignatureAlgorithm().getJCEId())
                    .build(tsa.getPrivateKey());
            TimeStampTokenGenerator gerador = new TimeStampTokenGenerator(
                    new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                            .setSignedAttributeGenerator(getSignedAttributeGenerator(genTime))
                            .build(assinador, new X509CertificateHolder(tsa.getCertificateToken().getEncoded())),
                    new JcaDigestCalculatorProviderBuilder().build().get(
                            new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()))),
                    new ASN1ObjectIdentifier(politica));
            gerador.setAccuracySeconds(accuracySegundos);
            gerador.addCertificates(new JcaCertStore(tsa.getCertificateChain().stream()
                    .map(CertificateToken::getCertificate).toList()));
            return new TimeStampResponseGenerator(gerador, TSPAlgorithms.ALLOWED);
        } catch (IOException | GeneralSecurityException | OperatorCreationException | TSPException e) {
            throw new DSSException("Falha ao preparar o carimbo simulado", e);
        }
    }
}
