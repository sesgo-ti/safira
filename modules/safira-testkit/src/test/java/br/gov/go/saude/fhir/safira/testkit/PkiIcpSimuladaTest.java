/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PkiIcpSimuladaTest {

    private static final String SAN_CPF = "2.16.76.1.3.1";
    private static final String SAN_CNPJ = "2.16.76.1.3.3";
    private static final String POLITICA_A3 = "2.16.76.1.2.3.1";
    private static final String EKU_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";

    private final PkiIcpSimulada pki = PkiIcpSimulada.criar();

    @Test
    void shouldIssueSignerWithIcpBrasilCpfOtherName() throws Exception {
        X509Certificate signatario = pki.signatario();

        assertThat(otherNames(signatario, SAN_CPF)).singleElement()
                .satisfies(valor -> {
                    // DOC-ICP-04: nascimento (8) + CPF (11) + NIS (11) + RG (15) + órgão/UF (6)
                    assertThat(valor).hasSize(51);
                    assertThat(valor.substring(8, 19)).isEqualTo(PkiIcpSimulada.CPF);
                });
        assertThat(rdn(signatario, BCStyle.SERIALNUMBER)).isEqualTo(PkiIcpSimulada.CPF);
        assertThat(signatario.getExtensionValue(Extension.certificatePolicies.getId())).isNotNull();
        assertThat(signatario.getNonCriticalExtensionOIDs()).contains(Extension.certificatePolicies.getId());
        assertThat(pki.revogado().getNonCriticalExtensionOIDs()).contains(Extension.certificatePolicies.getId());
        assertThat(politicas(signatario)).containsExactly(POLITICA_A3);
        assertThat(((RSAPublicKey) signatario.getPublicKey()).getModulus().bitLength()).isEqualTo(2048);
        assertThat(signatario.getKeyUsage()[0]).isTrue();
        assertThat(signatario.getKeyUsage()[1]).isTrue();
        assertThat(signatario.getBasicConstraints()).isEqualTo(-1);
    }

    @Test
    void shouldMarkEveryCertificateAsSimulation() {
        for (X509Certificate certificado : List.of(pki.raiz(), pki.ac(), pki.signatario(), pki.revogado(), pki.tsa())) {
            assertThat(rdn(certificado, BCStyle.O)).isEqualTo(PkiIcpSimulada.MARCA);
        }
    }

    @Test
    void shouldChainSignerToTrustAnchorThroughIntermediateCa() throws Exception {
        pki.signatario().verify(pki.ac().getPublicKey());
        pki.revogado().verify(pki.ac().getPublicKey());
        pki.tsa().verify(pki.ac().getPublicKey());
        pki.ac().verify(pki.raiz().getPublicKey());
        pki.raiz().verify(pki.raiz().getPublicKey());

        assertThat(pki.ac().getBasicConstraints()).isGreaterThanOrEqualTo(0);
        assertThat(pki.cadeia()).containsExactly(pki.signatario(), pki.ac(), pki.raiz());
        assertThat(pki.repositorio().getTrustAnchors()).singleElement()
                .satisfies(ancora -> assertThat(ancora.getCertificateToken()).isEqualTo(new CertificateToken(pki.raiz())));
        assertThat(pki.emissorSha256()).isEqualTo(sha256(pki.ac()));
        assertThat(pki.chavesSignatario().getPublic()).isEqualTo(pki.signatario().getPublicKey());
        assertThat(pki.chavesAc().getPublic()).isEqualTo(pki.ac().getPublicKey());
        assertThat(pki.inicioValidade()).isEqualTo(pki.signatario().getNotBefore().getTime() / 1000);
        assertThat(pki.fimValidade()).isEqualTo(pki.signatario().getNotAfter().getTime() / 1000);
    }

    @Test
    void shouldReportRevokedCertificateAsRevokedByOcspAndCrl() throws Exception {
        CertificateToken revogado = new CertificateToken(pki.revogado());
        CertificateToken ac = new CertificateToken(pki.ac());

        OCSPToken ocsp = pki.fonteOcsp().getRevocationToken(revogado, ac);
        CRLToken lcr = pki.fonteLcr().getRevocationToken(revogado, ac);

        assertThat(ocsp.getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(lcr.getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(status(pki.ocspRevogado(pki.signatario()))).isInstanceOf(RevokedStatus.class);
    }

    @Test
    void shouldReportSignerAndIntermediateCaAsGoodByOcsp() throws Exception {
        assertThat(pki.fonteOcsp().getRevocationToken(new CertificateToken(pki.signatario()),
                new CertificateToken(pki.ac())).getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(pki.fonteOcsp().getRevocationToken(new CertificateToken(pki.ac()),
                new CertificateToken(pki.raiz())).getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(status(pki.ocspBom(pki.signatario()))).isNull();
        assertThat(pki.fonteLcr().getRevocationToken(new CertificateToken(pki.signatario()),
                new CertificateToken(pki.ac())).getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(pki.lcr()).isNotEmpty();
    }

    @Test
    void shouldIssueEmptyRootCrlSignedByRoot() throws Exception {
        X509CRL lcr = (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(pki.lcrDaRaiz()));

        lcr.verify(pki.raiz().getPublicKey());
        assertThat(lcr.getIssuerX500Principal()).isEqualTo(pki.raiz().getSubjectX500Principal());
        assertThat(lcr.isRevoked(pki.ac())).isFalse();
        assertThat(lcr.getNextUpdate()).isAfter(new Date());
    }

    @Test
    void shouldIssueTimestampWithConfiguredPolicy() throws Exception {
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest("conteudo".getBytes());
        Date genTime = new Date((pki.inicioValidade() + 3600) * 1000);

        TimeStampToken token = new TimeStampToken(new CMSSignedData(
                pki.carimbo(imprint, OpcoesCarimbo.em(genTime).comAccuracy(2))));
        TimestampBinary binario = pki.fonteTsp().getTimeStampResponse(DigestAlgorithm.SHA256, imprint);

        assertThat(token.getTimeStampInfo().getPolicy().getId()).isEqualTo(PkiIcpSimulada.POLITICA_TSA);
        assertThat(token.getTimeStampInfo().getGenTime()).isEqualTo(genTime);
        assertThat(token.getTimeStampInfo().getAccuracy().getSeconds().intValueExact()).isEqualTo(2);
        assertThat(token.getTimeStampInfo().getMessageImprintDigest()).isEqualTo(imprint);
        assertThat(token.getSID().getSerialNumber()).isEqualTo(pki.tsa().getSerialNumber());
        assertThat(new TimeStampToken(new CMSSignedData(binario.getBytes())).getTimeStampInfo().getPolicy().getId())
                .isEqualTo(PkiIcpSimulada.POLITICA_TSA);
        assertThat(pki.tsa().getExtendedKeyUsage()).containsExactly(EKU_TIMESTAMPING);
        assertThat(pki.tsa().getCriticalExtensionOIDs()).contains(Extension.extendedKeyUsage.getId());
        assertThat(pki.tsaComEkuNaoCritico().getCriticalExtensionOIDs()).doesNotContain(Extension.extendedKeyUsage.getId());
        assertThat(pki.tsaComEkuNaoCritico().getPublicKey()).isEqualTo(pki.tsa().getPublicKey());
    }

    @Test
    void shouldServeTimestampOverLocalHttp() throws Exception {
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest("http".getBytes());
        TimeStampRequestGenerator gerador = new TimeStampRequestGenerator();
        gerador.setCertReq(true);
        byte[] requisicao = gerador.generate(TSPAlgorithms.SHA256, imprint, BigInteger.TEN).getEncoded();

        try (TsaHttpLocal tsa = pki.iniciarTsaHttp()) {
            HttpURLConnection conexao = (HttpURLConnection) URI.create(tsa.url()).toURL().openConnection();
            conexao.setDoOutput(true);
            conexao.setRequestProperty("Content-Type", "application/timestamp-query");
            try (OutputStream saida = conexao.getOutputStream()) {
                saida.write(requisicao);
            }
            TimeStampResponse resposta = new TimeStampResponse(conexao.getInputStream().readAllBytes());

            assertThat(tsa.url()).startsWith("http://127.0.0.1:").endsWith("/tsa");
            assertThat(resposta.getTimeStampToken().getTimeStampInfo().getNonce()).isEqualTo(BigInteger.TEN);
            assertThat(resposta.getTimeStampToken().getTimeStampInfo().getPolicy().getId())
                    .isEqualTo(PkiIcpSimulada.POLITICA_TSA);
            assertThat(resposta.getTimeStampToken().getSID().getSerialNumber())
                    .isEqualTo(tsa.certificado().getSerialNumber());
            assertThat(tsa.certificado().getPublicKey()).isEqualTo(pki.tsa().getPublicKey());
            tsa.certificado().verify(pki.ac().getPublicKey());

            String ocspUrl = tsa.url().replace("/tsa", "/ocsp");
            assertThat(CertificateExtensionsUtils.getOCSPAccessUrls(new CertificateToken(tsa.certificado())))
                    .containsExactly(ocspUrl);
            OCSPReq consulta = new OCSPReqBuilder().addRequest(new CertificateID(
                    new BcDigestCalculatorProvider().get(CertificateID.HASH_SHA1),
                    new X509CertificateHolder(pki.ac().getEncoded()), tsa.certificado().getSerialNumber())).build();
            HttpURLConnection ocsp = (HttpURLConnection) URI.create(ocspUrl).toURL().openConnection();
            ocsp.setDoOutput(true);
            ocsp.setRequestProperty("Content-Type", "application/ocsp-request");
            try (OutputStream saida = ocsp.getOutputStream()) {
                saida.write(consulta.getEncoded());
            }
            assertThat(status(ocsp.getInputStream().readAllBytes())).isNull();
        }
    }

    @Test
    void shouldApplyLeafProfileVariations() throws Exception {
        PkiIcpSimulada ec = PkiIcpSimulada.criar(PerfilSignatario.a3().comChave("EC", 256));
        PkiIcpSimulada rsa3072 = PkiIcpSimulada.criar(PerfilSignatario.a3().comChave("RSA", 3072));
        PkiIcpSimulada semNaoRepudio = PkiIcpSimulada.criar(PerfilSignatario.a3().comKeyUsage(KeyUsage.digitalSignature));
        PkiIcpSimulada selo = PkiIcpSimulada.criar(PerfilSignatario.seS());
        PkiIcpSimulada critica = PkiIcpSimulada.criar(PerfilSignatario.a3()
                .comDn("CN=Fulano").comPolitica("2.16.76.1.2.1.1").comExtensaoCriticaDesconhecida());

        assertThat(ec.signatario().getPublicKey()).isInstanceOf(ECPublicKey.class);
        assertThat(((RSAPublicKey) rsa3072.signatario().getPublicKey()).getModulus().bitLength()).isEqualTo(3072);
        assertThat(semNaoRepudio.signatario().getKeyUsage()[1]).isFalse();
        assertThat(otherNames(selo.signatario(), SAN_CNPJ)).containsExactly(PkiIcpSimulada.CNPJ);
        assertThat(politicas(selo.signatario())).containsExactly("2.16.76.1.2.201.1");
        assertThat(critica.signatario().getSubjectX500Principal().getName()).isEqualTo("CN=Fulano");
        assertThat(politicas(critica.signatario())).containsExactly("2.16.76.1.2.1.1");
        assertThat(critica.signatario().getCriticalExtensionOIDs()).contains("1.3.6.1.4.1.99999.1");
        critica.signatario().verify(critica.ac().getPublicKey());
        assertThat(critica.fonteOcsp().getRevocationToken(new CertificateToken(critica.signatario()),
                new CertificateToken(critica.ac())).getStatus()).isEqualTo(CertificateStatus.GOOD);
    }

    @Test
    void shouldNotCollideSerialsAcrossInstances() {
        PkiIcpSimulada outra = PkiIcpSimulada.criar();

        assertThat(outra.signatario().getSerialNumber()).isNotEqualTo(pki.signatario().getSerialNumber());
        assertThat(outra.ac().getSerialNumber()).isNotEqualTo(pki.ac().getSerialNumber());
        assertThat(outra.raiz().getPublicKey()).isNotEqualTo(pki.raiz().getPublicKey());
    }

    @Test
    void shouldIssueSignerWithConfiguredValidity() {
        PkiIcpSimulada curta = PkiIcpSimulada.criar(PerfilSignatario.a3().comValidade(Period.ofYears(2)));
        Instant agora = Instant.now();

        assertThat(curta.signatario().getNotAfter().toInstant())
                .isBetween(agora.plus(Duration.ofDays(729)), agora.plus(Duration.ofDays(732)))
                .isBefore(curta.ac().getNotAfter().toInstant());
    }

    @Test
    void shouldRestorePkiFromPersistedMaterialKeepingRevocation() throws Exception {
        PkiIcpSimulada.Material material = pki.material();

        PkiIcpSimulada restaurada = PkiIcpSimulada.restaurar(material, Duration.ofDays(7));
        CertificateToken ac = new CertificateToken(restaurada.ac());
        CRLToken lcr = restaurada.fonteLcr().getRevocationToken(new CertificateToken(restaurada.revogado()), ac);
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest("restaurada".getBytes());
        TimeStampToken carimbo = new TimeStampToken(new CMSSignedData(
                restaurada.fonteTsp().getTimeStampResponse(DigestAlgorithm.SHA256, imprint).getBytes()));

        assertThat(restaurada.cadeia()).isEqualTo(pki.cadeia());
        assertThat(restaurada.tsa()).isEqualTo(pki.tsa());
        assertThat(restaurada.revogadoEm()).isEqualTo(pki.revogadoEm());
        assertThat(restaurada.chavesSignatario().getPrivate()).isEqualTo(pki.chavesSignatario().getPrivate());
        assertThat(restaurada.fonteOcsp().getRevocationToken(new CertificateToken(restaurada.revogado()), ac)
                .getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(restaurada.fonteOcsp().getRevocationToken(new CertificateToken(restaurada.signatario()), ac)
                .getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(restaurada.fonteOcsp().getRevocationToken(ac, new CertificateToken(restaurada.raiz()))
                .getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(lcr.getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(lcr.getNextUpdate()).isBetween(Date.from(Instant.now().plus(Duration.ofDays(6))),
                Date.from(Instant.now().plus(Duration.ofDays(8))));
        assertThat(carimbo.getSID().getSerialNumber()).isEqualTo(pki.tsa().getSerialNumber());
        assertThat(carimbo.getTimeStampInfo().getPolicy().getId()).isEqualTo(PkiIcpSimulada.POLITICA_TSA);
    }

    @Test
    void shouldRenewSignerKeepingKeyAndIssuer() throws Exception {
        PkiIcpSimulada curta = PkiIcpSimulada.criar(PerfilSignatario.a3().comValidade(Period.ofDays(10)));
        X509Certificate antigo = curta.signatario();

        curta.renovarSignatario(Period.ofYears(2));
        X509Certificate novo = curta.signatario();

        novo.verify(curta.ac().getPublicKey());
        assertThat(novo.getPublicKey()).isEqualTo(antigo.getPublicKey());
        assertThat(novo.getSerialNumber()).isNotEqualTo(antigo.getSerialNumber());
        assertThat(novo.getSubjectX500Principal()).isEqualTo(antigo.getSubjectX500Principal());
        assertThat(novo.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .isEqualTo(antigo.getExtensionValue(Extension.subjectAlternativeName.getId()));
        assertThat(politicas(novo)).isEqualTo(politicas(antigo));
        assertThat(novo.getNotAfter().toInstant()).isAfter(Instant.now().plus(Duration.ofDays(700)));
        assertThat(curta.cadeia().getFirst()).isEqualTo(novo);
        assertThat(curta.fonteOcsp().getRevocationToken(new CertificateToken(novo),
                new CertificateToken(curta.ac())).getStatus()).isEqualTo(CertificateStatus.GOOD);
    }

    private static RevokedStatus status(byte[] ocspDer) throws Exception {
        BasicOCSPResp basica = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        return (RevokedStatus) basica.getResponses()[0].getCertStatus();
    }

    private static String rdn(X509Certificate certificado, ASN1ObjectIdentifier tipo) {
        X500Name nome = X500Name.getInstance(certificado.getSubjectX500Principal().getEncoded());
        return IETFUtils.valueToString(nome.getRDNs(tipo)[0].getFirst().getValue());
    }

    private static List<String> politicas(X509Certificate certificado) throws Exception {
        byte[] valor = certificado.getExtensionValue(Extension.certificatePolicies.getId());
        ASN1Sequence sequencia = ASN1Sequence.getInstance(
                ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(valor).getOctets()));
        List<String> oids = new ArrayList<>();
        sequencia.forEach(item -> oids.add(ASN1ObjectIdentifier.getInstance(
                ASN1Sequence.getInstance(item).getObjectAt(0)).getId()));
        return oids;
    }

    private static List<String> otherNames(X509Certificate certificado, String oid) throws Exception {
        byte[] valor = certificado.getExtensionValue(Extension.subjectAlternativeName.getId());
        GeneralNames nomes = GeneralNames.getInstance(
                ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(valor).getOctets()));
        List<String> valores = new ArrayList<>();
        for (GeneralName nome : nomes.getNames()) {
            if (nome.getTagNo() != GeneralName.otherName) {
                continue;
            }
            ASN1Sequence otherName = ASN1Sequence.getInstance(nome.getName());
            if (oid.equals(ASN1ObjectIdentifier.getInstance(otherName.getObjectAt(0)).getId())) {
                ASN1TaggedObject marcado = ASN1TaggedObject.getInstance(otherName.getObjectAt(1));
                valores.add(((ASN1String) marcado.getBaseObject().toASN1Primitive()).getString());
            }
        }
        return valores;
    }

    private static String sha256(X509Certificate certificado) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificado.getEncoded()));
    }
}
