/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain;

/**
 * Material criptográfico utilizado na assinatura digital.
 * Cada subtipo carrega as credenciais específicas do mecanismo de acesso à chave privada.
 */
public sealed interface CryptoMaterial permits 
    CryptoMaterial.PemMaterial, 
    CryptoMaterial.Pkcs12Material
    // TODO: implement other types of material as needed
//    CryptoMaterial.SmartcardMaterial,
//    CryptoMaterial.TokenMaterial,
//    CryptoMaterial.RemoteMaterial
{

    record PemMaterial(String privateKey, String password) implements CryptoMaterial {}
    
    record Pkcs12Material(String contentBase64, String password, String alias) implements CryptoMaterial {}
    
//    record SmartcardMaterial(String pin, String identifier, Integer slotId, String tokenLabel) implements CryptoMaterial {}
//
//    record TokenMaterial(String pin, String identifier, Integer slotId, String tokenLabel) implements CryptoMaterial {}
//
//    record RemoteMaterial(String serviceUrl, String credential) implements CryptoMaterial {}
}
