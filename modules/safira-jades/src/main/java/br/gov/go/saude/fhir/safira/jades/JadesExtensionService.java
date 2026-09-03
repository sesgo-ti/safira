/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Extensão de assinaturas JAdES para níveis superiores (ETSI TS 119 182-1 §6.3):
 *
 * <ul>
 *   <li><b>B-T</b>: incorpora {@code sigTst} (carimbo RFC 3161 sobre o signature value)
 *       dentro do container {@code etsiU} — requer {@link TSPSource};</li>
 *   <li><b>B-LT</b>: incorpora {@code xVals}/{@code rVals}/{@code tstVD} (material completo
 *       de validação) — requer fontes de revogação e âncoras de confiança no
 *       {@link CertificateVerifier};</li>
 *   <li><b>B-LTA</b>: incorpora {@code arcTst} (carimbo de arquivo) como último elemento
 *       do {@code etsiU}.</li>
 * </ul>
 *
 * <p>Os componentes do {@code etsiU} são incorporados em base64url (forma exigida para
 * atingir B-LTA; nunca misturar formas — §5.3.1).
 */
public class JadesExtensionService {

    /**
     * Estende o JWS para o nível alvo.
     *
     * @param jwsJson   JWS em General JSON Serialization
     * @param target    nível alvo ({@code JAdES_BASELINE_T}, {@code _LT} ou {@code _LTA})
     * @param tspSource fonte de carimbo do tempo (obrigatória para T/LT/LTA)
     * @param verifier  verificador com âncoras ICP-Brasil e fontes de revogação
     *                  (obrigatório para LT/LTA; para B-T pode ser um verifier vazio)
     * @return JWS estendido em General JSON Serialization
     */
    public String extend(String jwsJson, SignatureLevel target, TSPSource tspSource, CertificateVerifier verifier) {
        Objects.requireNonNull(jwsJson, "jwsJson não pode ser nulo");
        Objects.requireNonNull(target, "target não pode ser nulo");
        Objects.requireNonNull(verifier, "verifier não pode ser nulo");

        JAdESService service = new JAdESService(verifier);
        service.setTspSource(tspSource);

        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(target);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        parameters.setBase64UrlEncodedEtsiUComponents(true);

        DSSDocument extended = service.extendDocument(
                new InMemoryDocument(jwsJson.getBytes(StandardCharsets.UTF_8)), parameters);
        return new String(DSSUtils.toByteArray(extended), StandardCharsets.UTF_8);
    }
}
