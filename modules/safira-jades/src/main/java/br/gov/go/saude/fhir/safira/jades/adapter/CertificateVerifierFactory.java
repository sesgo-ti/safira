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
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Fábrica do {@link CommonCertificateVerifier} central do Safira: o EU DSS decide cadeia, AIA,
 * revogação (OCSP/CRL) e validade; o Safira só fornece os certificados.
 *
 * <ul>
 *   <li><b>confiáveis</b> ({@link CommonTrustedCertificateSource}): somente as raízes do acervo
 *       ICP-Brasil (e âncoras extras por chamada, como o trust store TSA da política) — o DSS
 *       trata certificado confiável como âncora e não verifica sua revogação;</li>
 *   <li><b>adjuntos</b> ({@link CommonCertificateSource}): ACs do acervo, candidatas à cadeia
 *       e revalidadas pelo DSS como qualquer outro certificado;</li>
 *   <li><b>rede</b>: OCSP, CRL e AIA pelo {@link RestrictedDataLoader}, com o
 *       {@link DestinationGuard} recebido.</li>
 * </ul>
 */
public final class CertificateVerifierFactory {

    /** Teto do corpo de resposta OCSP/CRL/AIA: comporta as maiores LCRs das ACs ICP-Brasil. */
    public static final int MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

    private static final String OCSP_CONTENT_TYPE = "application/ocsp-request";

    private final RevocationSource<OCSP> ocspSource;
    private final RevocationSource<CRL> crlSource;
    private final AIASource aiaSource;
    private final List<RestrictedDataLoader> dataLoaders;

    private CertificateVerifierFactory(RevocationSource<OCSP> ocspSource, RevocationSource<CRL> crlSource,
                                       AIASource aiaSource, List<RestrictedDataLoader> dataLoaders) {
        this.ocspSource = ocspSource;
        this.crlSource = crlSource;
        this.aiaSource = aiaSource;
        this.dataLoaders = dataLoaders;
    }

    /**
     * Fontes online do DSS (endereços tirados dos próprios certificados).
     *
     * @param ocspTimeoutSeconds timeout das consultas OCSP
     * @param crlTimeoutSeconds  timeout dos downloads de CRL e de certificados via AIA
     * @param guard              política de destino (anti-SSRF) aplicada na conexão
     */
    public static CertificateVerifierFactory online(int ocspTimeoutSeconds, int crlTimeoutSeconds,
                                                    DestinationGuard guard) {
        RestrictedDataLoader ocspLoader = new RestrictedDataLoader(OCSP_CONTENT_TYPE, ocspTimeoutSeconds, MAX_RESPONSE_BYTES, guard);
        RestrictedDataLoader crlLoader = new RestrictedDataLoader(null, crlTimeoutSeconds, MAX_RESPONSE_BYTES, guard);
        RestrictedDataLoader aiaLoader = new RestrictedDataLoader(null, crlTimeoutSeconds, MAX_RESPONSE_BYTES, guard);
        DefaultAIASource aia = new DefaultAIASource(aiaLoader);
        aia.setAcceptedProtocols(List.of(Protocol.HTTP, Protocol.HTTPS));
        return new CertificateVerifierFactory(new OnlineOCSPSource(ocspLoader), new OnlineCRLSource(crlLoader), aia,
                List.of(ocspLoader, crlLoader, aiaLoader));
    }

    /**
     * Fontes fornecidas pelo chamador e sem AIA — testes e evidências já coletadas.
     *
     * @param ocspSource fonte OCSP; pode ser nula
     * @param crlSource  fonte CRL; pode ser nula
     */
    public static CertificateVerifierFactory offline(RevocationSource<OCSP> ocspSource, RevocationSource<CRL> crlSource) {
        return new CertificateVerifierFactory(ocspSource, crlSource, null, List.of());
    }

    /**
     * Converte o acervo em fontes do DSS; reaproveitável enquanto o acervo não mudar.
     *
     * @param roots raízes confiáveis
     * @param cas   ACs candidatas à cadeia (não confiáveis por si)
     */
    public static Acervo acervo(Collection<X509Certificate> roots, Collection<X509Certificate> cas) {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        roots.forEach(root -> trusted.addCertificate(new CertificateToken(root)));
        CommonCertificateSource adjunct = new CommonCertificateSource();
        cas.forEach(ca -> adjunct.addCertificate(new CertificateToken(ca)));
        return new Acervo(trusted, adjunct);
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
        verifier.setAdjunctCertSources(acervo.adjunct());
        verifier.setOcspSource(ocspSource);
        verifier.setCrlSource(crlSource);
        verifier.setAIASource(aiaSource);
        return verifier;
    }

    /** Data loaders das fontes online, na ordem OCSP, CRL e AIA (vazio quando offline). */
    List<RestrictedDataLoader> dataLoaders() {
        return dataLoaders;
    }

    /** Raízes confiáveis e ACs adjuntas do acervo, já como fontes do DSS. */
    public record Acervo(CommonTrustedCertificateSource trusted, CommonCertificateSource adjunct) {
    }
}
