package br.gov.go.saude.fhir.safira.engine.domain;

/**
 * Marker interface for the different types of cryptographic material.
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
