/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Extensão JAdES-B-B → JAdES-B-T da política 0.2.0 (ETSI TS 119 182-1 §6.3; criar etapas 12–13).
 *
 * <p>Acrescenta ao objeto de assinatura somente {@code header.etsiU} com um único {@code sigTst}
 * (carimbo RFC 3161 sobre o valor textual de {@code signature}), em representação <em>clara</em>
 * e com o token em Base64 padrão. Os membros {@code payload}, {@code protected} e
 * {@code signature} do B-B permanecem inalterados. B-LT e B-LTA não são admitidos pela política
 * 0.2.0 (C15).
 */
public class JadesExtensionService {

    /**
     * @param jwsJson   JAdES-B-B em General JSON Serialization
     * @param tspSource fonte de carimbo do tempo (TSA com política e nonce)
     * @return JAdES-B-T em General JSON Serialization
     */
    public String extendToBaselineT(String jwsJson, TSPSource tspSource) {
        Objects.requireNonNull(jwsJson, "jwsJson não pode ser nulo");
        Objects.requireNonNull(tspSource, "tspSource não pode ser nulo");

        // B-T não consulta revogação: verificador vazio é suficiente
        JAdESService service = new JAdESService(new CommonCertificateVerifier());
        service.setTspSource(tspSource);

        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        // Política 0.2.0: etsiU em claro (L4 prevê base64url apenas para B-LT/B-LTA futuros)
        parameters.setBase64UrlEncodedEtsiUComponents(false);
        // messageImprint SHA-256 (criar 12.1/12.2); o padrão do DSS para carimbos é SHA-512
        parameters.getSignatureTimestampParameters().setDigestAlgorithm(DigestAlgorithm.SHA256);

        DSSDocument extended = service.extendDocument(
                new InMemoryDocument(jwsJson.getBytes(StandardCharsets.UTF_8)), parameters);
        return new String(DSSUtils.toByteArray(extended), StandardCharsets.UTF_8);
    }
}
