/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.JAXBPKILoader;
import eu.europa.esig.dss.pki.jaxb.PKIJaxbFacade;
import eu.europa.esig.dss.pki.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.pki.jaxb.XmlCertificateType;
import eu.europa.esig.dss.pki.jaxb.XmlKeyAlgo;
import eu.europa.esig.dss.pki.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.pki.jaxb.XmlPki;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * PKI ICP-like SIMULADA — SEM VALOR LEGAL — para testes e para o simulador.
 *
 * <p>Declarada em XML ({@code pki/icp-simulada.xml}) e gerada pela PKI factory do EU DSS
 * ({@code dss-pki-factory-jaxb}): raiz (âncora) → AC → signatário A3, signatário revogado e TSA.
 * Revogação e carimbo do tempo saem das fontes em memória do DSS ({@link PKIOCSPSource},
 * {@link PKICRLSource}, {@link PKITSPSource}), sem rede.
 *
 * <p>Cola BouncyCastle (o XML não expressa): o signatário e o revogado são reemitidos pela AC com DN
 * ICP-Brasil (SERIALNUMBER) e otherName CPF/CNPJ no SAN; variações de cenário de ataque
 * ({@link PerfilSignatario#comExtensaoCriticaDesconhecida()}, {@link #tsaComEkuNaoCritico()}) usam a
 * mesma reemissão.
 *
 * <p>Cada instância gera chaves novas e seriais aleatórios; datas relativas ao instante da criação.
 */
public final class PkiIcpSimulada {

    /** Marca presente no DN de todos os certificados. */
    public static final String MARCA = "SIMULACAO - SEM VALOR LEGAL";
    /** CPF (válido) do signatário A3. */
    public static final String CPF = "52998224725";
    /** CNPJ (válido) do signatário SE-S. */
    public static final String CNPJ = "11222333000181";
    /** Política dos carimbos emitidos pela TSA simulada. */
    public static final String POLITICA_TSA = "1.3.6.1.4.1.13762.3";

    private static final String XML = "/pki/icp-simulada.xml";
    private static final long RAIZ = 1;
    private static final long AC = 2;
    private static final long SIGNATARIO = 3;
    private static final long REVOGADO = 4;
    private static final long TSA = 5;
    private static final String EXTENSAO_DESCONHECIDA = "1.3.6.1.4.1.99999.1";
    private static final Duration VALIDADE_REVOGACAO = Duration.ofDays(3650);

    private final JAXBCertEntityRepository repositorio;
    private final JAXBCertEntity raiz;
    private final JAXBCertEntity ac;
    private final JAXBCertEntity signatario;
    private final JAXBCertEntity revogado;
    private final JAXBCertEntity tsa;
    private final Date proximaAtualizacao = Date.from(Instant.now().plus(VALIDADE_REVOGACAO));

    private PkiIcpSimulada(JAXBCertEntityRepository repositorio, long deslocamento) {
        this.repositorio = repositorio;
        this.raiz = entidade(RAIZ + deslocamento);
        this.ac = entidade(AC + deslocamento);
        this.signatario = entidade(SIGNATARIO + deslocamento);
        this.revogado = entidade(REVOGADO + deslocamento);
        this.tsa = entidade(TSA + deslocamento);
    }

    public static PkiIcpSimulada criar() {
        return criar(PerfilSignatario.a3());
    }

    public static PkiIcpSimulada criar(PerfilSignatario perfil) {
        XmlPki xml = carregarXml();
        long deslocamento = ThreadLocalRandom.current().nextLong(1L << 20, 1L << 52);
        for (XmlCertificateType certificado : xml.getCertificate()) {
            certificado.setSerialNumber(certificado.getSerialNumber() + deslocamento);
            certificado.getIssuer().setSerialNumber(certificado.getIssuer().getSerialNumber() + deslocamento);
            if (certificado.getSerialNumber() == SIGNATARIO + deslocamento) {
                aplicar(perfil, certificado);
            }
        }
        JAXBCertEntityRepository repositorio = new JAXBCertEntityRepository();
        new JAXBPKILoader().persistPKI(repositorio, xml);

        PkiIcpSimulada pki = new PkiIcpSimulada(repositorio, deslocamento);
        pki.reemitirComIdentidade(pki.signatario, perfil);
        pki.reemitirComIdentidade(pki.revogado, PerfilSignatario.pessoaFisica("Revogado"));
        return pki;
    }

    public X509Certificate raiz() {
        return certificado(raiz);
    }

    public X509Certificate ac() {
        return certificado(ac);
    }

    public X509Certificate signatario() {
        return certificado(signatario);
    }

    public X509Certificate revogado() {
        return certificado(revogado);
    }

    public X509Certificate tsa() {
        return certificado(tsa);
    }

    public KeyPair chavesAc() {
        return chaves(ac);
    }

    public KeyPair chavesSignatario() {
        return chaves(signatario);
    }

    public KeyPair chavesRevogado() {
        return chaves(revogado);
    }

    /** Cadeia completa do signatário: [signatário, AC, raiz]. */
    public List<X509Certificate> cadeia() {
        return List.of(signatario(), ac(), raiz());
    }

    /** SHA-256 (hex minúsculo) do DER da AC emissora — valor de {@code issuerSha256} na allowlist. */
    public String emissorSha256() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(ac().getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Chave privada do signatário em PEM, codificada em Base64 — formato aceito pelo crypto-signing. */
    public String chavePrivadaSignatarioPemBase64() {
        StringWriter texto = new StringWriter();
        try (JcaPEMWriter pem = new JcaPEMWriter(texto)) {
            pem.writeObject(signatario.getPrivateKey());
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao serializar a chave privada em PEM", e);
        }
        return Base64.getEncoder().encodeToString(texto.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** Início da validade do signatário (epoch em segundos). */
    public long inicioValidade() {
        return signatario().getNotBefore().getTime() / 1000;
    }

    /** Fim da validade do signatário (epoch em segundos). */
    public long fimValidade() {
        return signatario().getNotAfter().getTime() / 1000;
    }

    public JAXBCertEntityRepository repositorio() {
        return repositorio;
    }

    /** OCSP em memória: estado do repositório (o revogado consta REVOKED); demais certificados GOOD. */
    public PKIOCSPSource fonteOcsp() {
        return new OcspSimulado(repositorio, false, null, proximaAtualizacao);
    }

    /** LCR em memória emitida pelo emissor do certificado consultado. */
    public PKICRLSource fonteLcr() {
        return new LcrSimulada(repositorio, proximaAtualizacao);
    }

    /** Carimbo do tempo em memória pela TSA simulada, com {@link #POLITICA_TSA}. */
    public PKITSPSource fonteTsp() {
        return new TsaSimulada(tsa, POLITICA_TSA, null, null);
    }

    /** Resposta OCSP {@code GOOD} (DER de {@code OCSPResponse}) para o certificado, assinada pelo emissor. */
    public byte[] ocspBom(X509Certificate certificado) {
        return respostaOcsp(certificado, null);
    }

    /** Resposta OCSP {@code REVOKED} (motivo não especificado, revogado há uma hora). */
    public byte[] ocspRevogado(X509Certificate certificado) {
        return ocspRevogado(certificado, Date.from(Instant.now().minus(Duration.ofHours(1))));
    }

    /** Resposta OCSP {@code REVOKED} com a data de revogação informada. */
    public byte[] ocspRevogado(X509Certificate certificado, Date dataRevogacao) {
        return respostaOcsp(certificado, new CertEntityRevocation(dataRevogacao, RevocationReason.UNSPECIFIED));
    }

    /** LCR (DER) da AC, que lista o certificado revogado. */
    public byte[] lcr() {
        return new LcrSimulada(repositorio, proximaAtualizacao).lcrDer(ac);
    }

    /** {@code TimeStampToken} (CMS DER) sobre o hash SHA-256 informado, emitido pela TSA simulada. */
    public byte[] carimbo(byte[] sha256, OpcoesCarimbo opcoes) {
        return new TsaSimulada(tsa, opcoes.politica(), opcoes.genTime(), opcoes.accuracySegundos())
                .getTimeStampResponse(DigestAlgorithm.SHA256, sha256).getBytes();
    }

    /** Certificado da TSA com EKU id-kp-timeStamping NÃO crítico (mesma chave; cenário de ataque). */
    public X509Certificate tsaComEkuNaoCritico() {
        try {
            Extension eku = new Extension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping).getEncoded());
            return Reemissao.reemitir(tsa(), ac.getPrivateKey(), null, List.of(eku));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Sobe o stub HTTP RFC 3161 da TSA simulada em {@code 127.0.0.1}. */
    public TsaHttpLocal iniciarTsaHttp() {
        return new TsaHttpLocal(new TsaSimulada(tsa, POLITICA_TSA, null, null));
    }

    private byte[] respostaOcsp(X509Certificate certificado, CertEntityRevocation status) {
        return new OcspSimulado(repositorio, true, status, proximaAtualizacao)
                .respostaDer(new CertificateToken(certificado), emissorDe(certificado));
    }

    private CertificateToken emissorDe(X509Certificate certificado) {
        for (JAXBCertEntity candidato : repositorio.getAll()) {
            X509Certificate emissor = certificado(candidato);
            if (emissor.getSubjectX500Principal().equals(certificado.getIssuerX500Principal())) {
                try {
                    certificado.verify(emissor.getPublicKey());
                    return candidato.getCertificateToken();
                } catch (GeneralSecurityException e) {
                    // outro emissor com o mesmo DN
                }
            }
        }
        return ac.getCertificateToken();
    }

    private void reemitirComIdentidade(JAXBCertEntity entidade, PerfilSignatario perfil) {
        try {
            List<Extension> extensoes = new ArrayList<>();
            if (perfil.sanOid() != null) {
                extensoes.add(Reemissao.sanOtherName(perfil.sanOid(), perfil.sanValor()));
            }
            if (perfil.extensaoCriticaDesconhecida()) {
                extensoes.add(new Extension(new ASN1ObjectIdentifier(EXTENSAO_DESCONHECIDA), true,
                        new DERUTF8String("x").getEncoded()));
            }
            X509Certificate reemitido = Reemissao.reemitir(certificado(entidade), ac.getPrivateKey(),
                    perfil.dn(), extensoes);
            entidade.setCertificateToken(new CertificateToken(reemitido));
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao reemitir o signatário simulado", e);
        }
    }

    private static void aplicar(PerfilSignatario perfil, XmlCertificateType certificado) {
        XmlCertificatePolicies politicas = null;
        if (perfil.politica() != null) {
            politicas = new XmlCertificatePolicies();
            politicas.getCertificatePolicy().add(perfil.politica());
        }
        certificado.setCertificatePolicies(politicas);

        XmlKeyUsages usos = new XmlKeyUsages();
        for (KeyUsageBit bit : KeyUsageBit.values()) {
            if ((perfil.keyUsage() & bit.getBit()) != 0) {
                usos.getKeyUsage().add(bit);
            }
        }
        certificado.setKeyUsages(usos);

        XmlKeyAlgo algoritmo = new XmlKeyAlgo();
        if ("EC".equalsIgnoreCase(perfil.algoritmo())) {
            algoritmo.setEncryption(EncryptionAlgorithm.ECDSA);
            algoritmo.setLength(perfil.bitsChave() <= 0 ? 256 : perfil.bitsChave());
        } else {
            algoritmo.setEncryption(EncryptionAlgorithm.RSA);
            algoritmo.setLength(perfil.bitsChave());
        }
        certificado.setKeyAlgo(algoritmo);
    }

    private static XmlPki carregarXml() {
        try (InputStream entrada = PkiIcpSimulada.class.getResourceAsStream(XML)) {
            return PKIJaxbFacade.newFacade().unmarshall(entrada);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar " + XML, e);
        }
    }

    private JAXBCertEntity entidade(long serial) {
        return repositorio.getAll().stream()
                .filter(entidade -> entidade.getSerialNumber() == serial)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Certificado de serial " + serial + " ausente da PKI"));
    }

    private static X509Certificate certificado(JAXBCertEntity entidade) {
        return entidade.getCertificateToken().getCertificate();
    }

    private static KeyPair chaves(JAXBCertEntity entidade) {
        return new KeyPair(certificado(entidade).getPublicKey(), entidade.getPrivateKey());
    }
}
