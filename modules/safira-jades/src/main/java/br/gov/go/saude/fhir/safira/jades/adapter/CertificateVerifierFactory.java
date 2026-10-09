/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Fábrica do {@link CommonCertificateVerifier} central do Safira: o EU DSS decide cadeia,
 * revogação (OCSP/CRL) e validade; o Safira só fornece os certificados.
 *
 * <ul>
 *   <li><b>confiáveis</b> ({@link CommonTrustedCertificateSource}): somente as raízes do acervo
 *       ICP-Brasil (e âncoras extras por chamada, como o trust store TSA da política) — o DSS
 *       trata certificado confiável como âncora e não verifica sua revogação;</li>
 *   <li><b>adjuntos</b> ({@link CommonCertificateSource}): ACs do acervo, candidatas à cadeia
 *       e revalidadas pelo DSS como qualquer outro certificado; uma fonte nova por verificador,
 *       pois o DSS não admite compartilhar a adjunta entre operações (doc. §20.2.1);</li>
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
        return online(ocspTimeoutSeconds, crlTimeoutSeconds, guard, RestrictedDataLoader.DEFAULT_PORTS);
    }

    /** Como {@link #online(int, int, DestinationGuard)}, com portas admitidas explícitas (testes). */
    static CertificateVerifierFactory online(int ocspTimeoutSeconds, int crlTimeoutSeconds, DestinationGuard guard,
                                             Set<Integer> allowedPorts) {
        RestrictedDataLoader ocspLoader = new RestrictedDataLoader(OCSP_CONTENT_TYPE, ocspTimeoutSeconds,
                MAX_RESPONSE_BYTES, guard, allowedPorts);
        RestrictedDataLoader crlLoader = new RestrictedDataLoader(null, crlTimeoutSeconds,
                MAX_RESPONSE_BYTES, guard, allowedPorts);
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
     * Converte o acervo para o DSS; reaproveitável enquanto o acervo não mudar.
     *
     * @param roots raízes confiáveis
     * @param cas   ACs candidatas à cadeia (não confiáveis por si)
     */
    public static Acervo acervo(Collection<X509Certificate> roots, Collection<X509Certificate> cas) {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        roots.forEach(root -> trusted.addCertificate(new CertificateToken(root)));
        return new Acervo(trusted, cas.stream().map(CertificateToken::new).toList());
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
        acervo.cas().forEach(adjunct::addCertificate);
        verifier.setAdjunctCertSources(adjunct);
        verifier.setOcspSource(ocspSource);
        verifier.setCrlSource(crlSource);
        verifier.setAIASource(null);
        verifier.setCheckRevocationForUntrustedChains(false);
        return verifier;
    }

    /** Data loaders das fontes online, na ordem OCSP e CRL (vazio quando offline). */
    List<RestrictedDataLoader> dataLoaders() {
        return dataLoaders;
    }

    /**
     * Acervo já convertido para o DSS: a fonte confiável é compartilhada entre verificadores (nunca
     * alterada depois de pronta); as ACs viram uma fonte adjunta nova a cada {@link #create}.
     *
     * @param trusted raízes confiáveis
     * @param cas     ACs candidatas à cadeia
     */
    public record Acervo(CommonTrustedCertificateSource trusted, List<CertificateToken> cas) {

        public Acervo {
            cas = List.copyOf(cas);
        }
    }
}
