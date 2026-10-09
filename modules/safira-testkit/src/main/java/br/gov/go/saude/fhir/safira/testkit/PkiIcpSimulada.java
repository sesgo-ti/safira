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
import eu.europa.esig.dss.pki.jaxb.XmlDateDefinitionType;
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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

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
 * {@link #restaurar(Material, Duration)} reconstrói uma PKI a partir do {@link #material()} persistido
 * (mesmas chaves e certificados, revogado ainda revogado).
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
    private static final String PKI = "icp-simulada";
    private static final long RAIZ = 1;
    private static final long AC = 2;
    private static final long SIGNATARIO = 3;
    private static final long REVOGADO = 4;
    private static final long TSA = 5;
    private static final String EXTENSAO_DESCONHECIDA = "1.3.6.1.4.1.99999.1";
    private static final Duration VALIDADE_REVOGACAO = Duration.ofDays(3650);
    private static final SecureRandom SERIAIS = new SecureRandom();

    private final JAXBCertEntityRepository repositorio;
    private final JAXBCertEntity raiz;
    private final JAXBCertEntity ac;
    private final JAXBCertEntity signatario;
    private final JAXBCertEntity revogado;
    private final JAXBCertEntity tsa;
    private final Supplier<Date> proximaAtualizacao;

    private PkiIcpSimulada(JAXBCertEntityRepository repositorio, JAXBCertEntity raiz, JAXBCertEntity ac,
                           JAXBCertEntity signatario, JAXBCertEntity revogado, JAXBCertEntity tsa,
                           Supplier<Date> proximaAtualizacao) {
        this.repositorio = repositorio;
        this.raiz = raiz;
        this.ac = ac;
        this.signatario = signatario;
        this.revogado = revogado;
        this.tsa = tsa;
        this.proximaAtualizacao = proximaAtualizacao;
    }

    /** Certificado e chave privada de uma entidade da PKI. */
    public record Entidade(X509Certificate certificado, PrivateKey chave) {
    }

    /**
     * Material que basta para reconstruir a PKI ({@link #restaurar(Material, Duration)}).
     *
     * @param revogadoEm instante da revogação do signatário revogado
     */
    public record Material(Entidade raiz, Entidade ac, Entidade signatario, Entidade revogado, Entidade tsa,
                           Date revogadoEm) {
    }

    public static PkiIcpSimulada criar() {
        return criar(PerfilSignatario.a3());
    }

    public static PkiIcpSimulada criar(PerfilSignatario perfil) {
        XmlPki xml = carregarXml();
        // Seriais imprevisíveis com ao menos 57 bits (o XML só admite long): deslocamento SecureRandom.
        long deslocamento = SERIAIS.nextLong(1L << 56, 1L << 62);
        for (XmlCertificateType certificado : xml.getCertificate()) {
            certificado.setSerialNumber(certificado.getSerialNumber() + deslocamento);
            certificado.getIssuer().setSerialNumber(certificado.getIssuer().getSerialNumber() + deslocamento);
            if (certificado.getSerialNumber() == SIGNATARIO + deslocamento) {
                aplicar(perfil, certificado);
            }
        }
        JAXBCertEntityRepository repositorio = new JAXBCertEntityRepository();
        new JAXBPKILoader().persistPKI(repositorio, xml);

        Date validadeFixa = Date.from(Instant.now().plus(VALIDADE_REVOGACAO));
        PkiIcpSimulada pki = new PkiIcpSimulada(repositorio, entidade(repositorio, RAIZ + deslocamento),
                entidade(repositorio, AC + deslocamento), entidade(repositorio, SIGNATARIO + deslocamento),
                entidade(repositorio, REVOGADO + deslocamento), entidade(repositorio, TSA + deslocamento),
                () -> validadeFixa);
        pki.reemitirComIdentidade(pki.signatario, perfil);
        pki.reemitirComIdentidade(pki.revogado, PerfilSignatario.pessoaFisica("Revogado"));
        return pki;
    }

    /**
     * Reconstrói a PKI a partir do material persistido: mesmas chaves e certificados e o revogado
     * revogado em {@link Material#revogadoEm()} (keyCompromise). OCSP e LCR saem com {@code nextUpdate}
     * de {@code validadeRevogacao} a partir de cada emissão (validade curta, sempre renovada).
     */
    public static PkiIcpSimulada restaurar(Material material, Duration validadeRevogacao) {
        JAXBCertEntityRepository repositorio = new JAXBCertEntityRepository();
        JAXBCertEntity raiz = restaurarEntidade(repositorio, material.raiz(), null);
        raiz.setTrustAnchor(true);
        JAXBCertEntity ac = restaurarEntidade(repositorio, material.ac(), raiz);
        JAXBCertEntity revogado = restaurarEntidade(repositorio, material.revogado(), ac);
        revogado.setRevocationDate(material.revogadoEm());
        revogado.setRevocationReason(RevocationReason.KEY_COMPROMISE);
        return new PkiIcpSimulada(repositorio, raiz, ac, restaurarEntidade(repositorio, material.signatario(), ac),
                revogado, restaurarEntidade(repositorio, material.tsa(), ac),
                () -> Date.from(Instant.now().plus(validadeRevogacao)));
    }

    /** Material para persistir a PKI e restaurá-la depois ({@link #restaurar(Material, Duration)}). */
    public Material material() {
        return new Material(entidadeDe(raiz), entidadeDe(ac), entidadeDe(signatario), entidadeDe(revogado),
                entidadeDe(tsa), revogadoEm());
    }

    /** Instante da revogação do signatário revogado. */
    public Date revogadoEm() {
        return revogado.getRevocationDate();
    }

    /**
     * Renova o certificado do signatário pela mesma AC: mesma chave, DN e extensões, serial novo e
     * validade {@code validade} a partir de agora (limitada à da AC). O certificado anterior deixa de
     * constar no repositório (OCSP e LCR o tratam como não revogado).
     */
    public void renovarSignatario(Period validade) {
        Instant agora = Instant.now();
        Date fim = Date.from(agora.atZone(ZoneOffset.UTC).plus(validade).toInstant());
        if (fim.after(ac().getNotAfter())) {
            fim = ac().getNotAfter();
        }
        long serial = SERIAIS.nextLong(1L << 56, 1L << 62);
        X509Certificate renovado = Reemissao.renovar(signatario(), ac.getPrivateKey(), BigInteger.valueOf(serial),
                Date.from(agora.minus(Duration.ofDays(1))), fim);
        signatario.setSerialNumber(serial);
        signatario.setCertificateToken(new CertificateToken(renovado));
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

    public KeyPair chavesRaiz() {
        return chaves(raiz);
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

    public KeyPair chavesTsa() {
        return chaves(tsa);
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

    /**
     * Respostas OCSP por certificado com o signatário {@code REVOKED} e os demais (AC, TSA) {@code GOOD}:
     * isola a revogação na folha (uso com {@code EvidenceRevocationSources.ocspPorCertificado}).
     */
    public Function<X509Certificate, byte[]> respostasComSignatarioRevogado() {
        return certificado -> certificado.equals(signatario()) ? ocspRevogado(certificado) : ocspBom(certificado);
    }

    /** Respostas OCSP por certificado sem resposta para o signatário e {@code GOOD} para os demais. */
    public Function<X509Certificate, byte[]> respostasSemRevogacaoDoSignatario() {
        return certificado -> certificado.equals(signatario()) ? null : ocspBom(certificado);
    }

    /** Respostas OCSP por certificado com a AC {@code REVOKED} e os demais (signatário, TSA) {@code GOOD}. */
    public Function<X509Certificate, byte[]> respostasComAcRevogada() {
        return certificado -> certificado.equals(ac()) ? ocspRevogado(certificado) : ocspBom(certificado);
    }

    /** Respostas OCSP por certificado sem resposta para a AC e {@code GOOD} para os demais. */
    public Function<X509Certificate, byte[]> respostasSemRevogacaoDaAc() {
        return certificado -> certificado.equals(ac()) ? null : ocspBom(certificado);
    }

    /** LCR (DER) da AC, que lista o certificado revogado. */
    public byte[] lcr() {
        return new LcrSimulada(repositorio, proximaAtualizacao).lcrDer(ac);
    }

    /** LCR (DER) da raiz, sem revogações: revogação da AC para quem usa LCRs em arquivo. */
    public byte[] lcrDaRaiz() {
        return new LcrSimulada(repositorio, proximaAtualizacao).lcrDer(raiz);
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

    /** Sobe o stub HTTP da TSA simulada ({@code /tsa} e {@code /ocsp}) em {@code 127.0.0.1}. */
    public TsaHttpLocal iniciarTsaHttp() {
        return new TsaHttpLocal(this);
    }

    /** Certificado da TSA reemitido com AIA OCSP para {@code urlOcsp} (mesma chave). */
    X509Certificate tsaComOcsp(String urlOcsp) {
        try {
            Extension aia = new Extension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                    AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, urlOcsp)).getEncoded());
            return Reemissao.reemitir(tsa(), ac.getPrivateKey(), null, List.of(aia));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    TsaSimulada tsaServida(X509Certificate certificado) {
        return new TsaSimulada(tsa, List.of(certificado, ac(), raiz()), POLITICA_TSA, null, null);
    }

    /** Resposta OCSP {@code GOOD}, assinada pela AC, a uma requisição recebida (eco do CertID e do nonce). */
    byte[] ocspBomPara(byte[] requisicaoDer) {
        return new OcspSimulado(repositorio, true, null, proximaAtualizacao)
                .respostaDer(requisicaoDer, tsa.getCertificateToken(), ac.getCertificateToken());
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
            byte[] politicas = certificado(entidade).getExtensionValue(Extension.certificatePolicies.getId());
            if (politicas != null) {
                // o DSS marca certificatePolicies crítica; nos certificados ICP-Brasil ela não é
                extensoes.add(new Extension(Extension.certificatePolicies, false,
                        ASN1OctetString.getInstance(politicas).getOctets()));
            }
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

        if (perfil.validade() != null) {
            XmlDateDefinitionType fim = new XmlDateDefinitionType();
            fim.setYear(perfil.validade().getYears());
            fim.setMonth(perfil.validade().getMonths());
            fim.setDay(perfil.validade().getDays());
            certificado.setNotAfter(fim);
        }
    }

    private static XmlPki carregarXml() {
        try (InputStream entrada = PkiIcpSimulada.class.getResourceAsStream(XML)) {
            return PKIJaxbFacade.newFacade().unmarshall(entrada);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar " + XML, e);
        }
    }

    private static JAXBCertEntity entidade(JAXBCertEntityRepository repositorio, long serial) {
        return repositorio.getAll().stream()
                .filter(entidade -> entidade.getSerialNumber() == serial)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Certificado de serial " + serial + " ausente da PKI"));
    }

    private static JAXBCertEntity restaurarEntidade(JAXBCertEntityRepository repositorio, Entidade material,
                                                    JAXBCertEntity emissor) {
        JAXBCertEntity entidade = new JAXBCertEntity();
        X509Certificate certificado = material.certificado();
        entidade.setSubject(certificado.getSubjectX500Principal().getName());
        entidade.setSerialNumber(certificado.getSerialNumber().longValueExact());
        entidade.setCertificateToken(new CertificateToken(certificado));
        entidade.setPrivateKeyBinaries(material.chave().getEncoded());
        entidade.setIssuer(emissor == null ? entidade : emissor);
        entidade.setPkiName(PKI);
        repositorio.save(entidade);
        return entidade;
    }

    private static Entidade entidadeDe(JAXBCertEntity entidade) {
        return new Entidade(certificado(entidade), entidade.getPrivateKey());
    }

    private static X509Certificate certificado(JAXBCertEntity entidade) {
        return entidade.getCertificateToken().getCertificate();
    }

    private static KeyPair chaves(JAXBCertEntity entidade) {
        return new KeyPair(certificado(entidade).getPublicKey(), entidade.getPrivateKey());
    }
}
