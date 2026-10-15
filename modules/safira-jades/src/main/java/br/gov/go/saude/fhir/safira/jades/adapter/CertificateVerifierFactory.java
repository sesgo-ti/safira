/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Fábrica do {@link CommonCertificateVerifier} central do Safira: o EU DSS decide cadeia,
 * revogação (OCSP/CRL) e validade; o Safira só fornece os certificados.
 *
 * <ul>
 *   <li><b>confiáveis</b> ({@link CommonTrustedCertificateSource}): somente as raízes do acervo
 *       ICP-Brasil (e âncoras extras por chamada, como o trust store TSA da política) — o DSS
 *       trata certificado confiável como âncora e não verifica sua revogação;</li>
 *   <li><b>adjuntos</b> ({@link CommonCertificateSource}): ACs do acervo, candidatas à cadeia
 *       e revalidadas pelo DSS como qualquer outro certificado; fonte e {@link CertificateToken}s
 *       novos por verificador, pois a adjunta é própria de cada operação (doc. do DSS §20.2.1) e o
 *       DSS grava no token o resultado da verificação de assinatura (emissor, validade);</li>
 *   <li><b>rede</b>: somente OCSP e CRL, pelo {@link RestrictedDataLoader} com o
 *       {@link DestinationGuard} recebido, e somente para cadeias que terminam numa âncora
 *       ({@code checkRevocationForUntrustedChains=false}, padrão do DSS 6.5 fixado aqui) — as
 *       URLs consultadas vêm de certificados emitidos por ACs confiáveis.</li>
 * </ul>
 *
 * <p>Sem AIA: a cadeia é montada pelo {@code x5c} e pelas ACs do acervo. Um {@code caIssuers}
 * de certificado forjado no {@code x5c} levaria o DSS a baixar de qualquer host (SSRF cego).
 */
public final class CertificateVerifierFactory {

    /** Teto do corpo de resposta OCSP/CRL: comporta as maiores LCRs das ACs ICP-Brasil. */
    public static final int MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

    private static final Logger log = LoggerFactory.getLogger(CertificateVerifierFactory.class);

    private static final String OCSP_CONTENT_TYPE = "application/ocsp-request";

    private final RevocationSource<OCSP> ocspSource;
    private final RevocationSource<CRL> crlSource;
    private final List<RestrictedDataLoader> dataLoaders;

    private CertificateVerifierFactory(RevocationSource<OCSP> ocspSource, RevocationSource<CRL> crlSource,
                                       List<RestrictedDataLoader> dataLoaders) {
        this.ocspSource = ocspSource;
        this.crlSource = crlSource;
        this.dataLoaders = dataLoaders;
    }

    /**
     * Fontes online do DSS (endereços tirados dos próprios certificados).
     *
     * @param ocspTimeoutSeconds timeout das consultas OCSP
     * @param crlTimeoutSeconds  timeout dos downloads de CRL
     * @param guard              política de destino (anti-SSRF) aplicada na conexão
     */
    public static CertificateVerifierFactory online(int ocspTimeoutSeconds, int crlTimeoutSeconds,
                                                    DestinationGuard guard) {
        RestrictedDataLoader ocspLoader = new RestrictedDataLoader(OCSP_CONTENT_TYPE, ocspTimeoutSeconds,
                MAX_RESPONSE_BYTES, guard);
        RestrictedDataLoader crlLoader = new RestrictedDataLoader(null, crlTimeoutSeconds,
                MAX_RESPONSE_BYTES, guard);
        return new CertificateVerifierFactory(new OnlineOCSPSource(ocspLoader), new OnlineCRLSource(crlLoader),
                List.of(ocspLoader, crlLoader));
    }

    /**
     * Fontes de revogação fornecidas pelo chamador — testes e evidências já coletadas.
     *
     * @param ocspSource fonte OCSP; pode ser nula
     * @param crlSource  fonte CRL; pode ser nula
     */
    public static CertificateVerifierFactory offline(RevocationSource<OCSP> ocspSource, RevocationSource<CRL> crlSource) {
        return new CertificateVerifierFactory(ocspSource, crlSource, List.of());
    }

    /**
     * Converte o acervo para o DSS; reaproveitável enquanto o acervo não mudar. Certificados que o
     * DSS não representa são ignorados com um WARN cada (o resto do acervo segue valendo); sem
     * nenhuma raiz representável o acervo não é {@linkplain Acervo#utilizavel() utilizável}.
     *
     * @param roots raízes confiáveis
     * @param cas   ACs candidatas à cadeia (não confiáveis por si)
     */
    public static Acervo acervo(Collection<X509Certificate> roots, Collection<X509Certificate> cas) {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        roots.forEach(root -> representavel(root, "raiz").ifPresent(trusted::addCertificate));
        List<X509Certificate> usableCas = cas.stream()
                .filter(ca -> representavel(ca, "intermediária").isPresent())
                .toList();
        return new Acervo(trusted, usableCas);
    }

    private static Optional<CertificateToken> representavel(X509Certificate certificate, String papel) {
        Optional<CertificateToken> token = token(certificate);
        if (token.isEmpty()) {
            log.warn("Certificado {} do acervo ignorado: o EU DSS não suporta o algoritmo de assinatura {} "
                            + "(subject: {}; SHA-256: {})", papel, certificate.getSigAlgOID(),
                    certificate.getSubjectX500Principal().getName(), sha256(certificate));
        }
        return token;
    }

    private static String sha256(X509Certificate certificate) {
        try {
            return HexFormat.of().withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            return "indisponível";
        }
    }

    /**
     * Novo verificador sobre o acervo, com âncoras extras desta chamada.
     *
     * @param acervo       fontes de {@link #acervo}
     * @param extraTrusted âncoras adicionais (ex.: trust store TSA da política); pode ser vazia
     */
    public CommonCertificateVerifier create(Acervo acervo, Collection<X509Certificate> extraTrusted) {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
        if (extraTrusted.isEmpty()) {
            verifier.setTrustedCertSources(acervo.trusted());
        } else {
            CommonTrustedCertificateSource extra = new CommonTrustedCertificateSource();
            extraTrusted.forEach(anchor -> extra.addCertificate(new CertificateToken(anchor)));
            verifier.setTrustedCertSources(acervo.trusted(), extra);
        }
        CommonCertificateSource adjunct = new CommonCertificateSource();
        acervo.cas().forEach(ca -> token(ca).ifPresent(adjunct::addCertificate));
        verifier.setAdjunctCertSources(adjunct);
        verifier.setOcspSource(ocspSource);
        verifier.setCrlSource(crlSource);
        verifier.setAIASource(null);
        verifier.setCheckRevocationForUntrustedChains(false);
        return verifier;
    }

    /**
     * Token do DSS para o certificado, ou vazio quando o DSS não o representa (ex.: algoritmo de
     * assinatura desconhecido, como o da raiz ICP-Brasil v7).
     */
    public static Optional<CertificateToken> token(X509Certificate certificate) {
        try {
            return Optional.of(new CertificateToken(certificate));
        } catch (IllegalArgumentException | DSSException e) {
            return Optional.empty();
        }
    }

    /** Data loaders das fontes online, na ordem OCSP e CRL (vazio quando offline). */
    List<RestrictedDataLoader> dataLoaders() {
        return dataLoaders;
    }

    /**
     * Acervo pronto para o DSS: a fonte confiável é compartilhada entre verificadores (nunca
     * alterada depois de pronta, como admite a doc. do DSS §20.2.1); as ACs ficam como certificados
     * e viram fonte adjunta e tokens novos a cada {@link #create}.
     *
     * @param trusted raízes confiáveis
     * @param cas     ACs candidatas à cadeia
     */
    public record Acervo(CommonTrustedCertificateSource trusted, List<X509Certificate> cas) {

        public Acervo {
            cas = List.copyOf(cas);
        }

        /** Se há ao menos uma raiz representável pelo DSS; sem ela, o acervo é indisponível. */
        public boolean utilizavel() {
            return !trusted.getCertificates().isEmpty();
        }
    }
}
