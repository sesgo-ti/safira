/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Única cola BouncyCastle do testkit: reemite, com a chave do mesmo emissor, um certificado gerado
 * pela PKI factory do DSS, trocando o DN e acrescentando/substituindo extensões que o XML não expressa
 * (otherName ICP-Brasil no SAN; variações de cenário de ataque). Serial, validade, chave pública e as
 * demais extensões do DSS são mantidos.
 */
final class Reemissao {

    private static final String ASSINATURA = "SHA256withRSA";

    private Reemissao() {
    }

    static X509Certificate reemitir(X509Certificate original, PrivateKey chaveEmissor, String dn,
                                    List<Extension> extensoes) {
        try {
            X509CertificateHolder base = new JcaX509CertificateHolder(original);
            X509v3CertificateBuilder construtor = new X509v3CertificateBuilder(base.getIssuer(),
                    base.getSerialNumber(), base.getNotBefore(), base.getNotAfter(),
                    dn == null ? base.getSubject() : new X500Name(dn), base.getSubjectPublicKeyInfo());
            Set<ASN1ObjectIdentifier> substituidas = extensoes.stream()
                    .map(Extension::getExtnId).collect(Collectors.toSet());
            for (Object oid : base.getExtensionOIDs()) {
                if (!substituidas.contains(oid)) {
                    construtor.addExtension(base.getExtension((ASN1ObjectIdentifier) oid));
                }
            }
            for (Extension extensao : extensoes) {
                construtor.addExtension(extensao);
            }
            return new JcaX509CertificateConverter().getCertificate(
                    construtor.build(new JcaContentSignerBuilder(ASSINATURA).build(chaveEmissor)));
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("Falha ao reemitir certificado da PKI simulada", e);
        }
    }

    /** Renova o certificado pelo mesmo emissor: mesma chave, DN e extensões; serial e validade novos. */
    static X509Certificate renovar(X509Certificate original, PrivateKey chaveEmissor, BigInteger serial,
                                   Date inicio, Date fim) {
        try {
            X509CertificateHolder base = new JcaX509CertificateHolder(original);
            X509v3CertificateBuilder construtor = new X509v3CertificateBuilder(base.getIssuer(), serial, inicio, fim,
                    base.getSubject(), base.getSubjectPublicKeyInfo());
            for (Object oid : base.getExtensionOIDs()) {
                construtor.addExtension(base.getExtension((ASN1ObjectIdentifier) oid));
            }
            return new JcaX509CertificateConverter().getCertificate(
                    construtor.build(new JcaContentSignerBuilder(ASSINATURA).build(chaveEmissor)));
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("Falha ao renovar certificado da PKI simulada", e);
        }
    }

    /** SAN com um otherName ICP-Brasil ({@code 2.16.76.1.3.x}) em UTF8String explícito. */
    static Extension sanOtherName(String oid, String valor) throws IOException {
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(oid));
        otherName.add(new DERTaggedObject(true, 0, new DERUTF8String(valor)));
        return new Extension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(otherName))).getEncoded());
    }
}
