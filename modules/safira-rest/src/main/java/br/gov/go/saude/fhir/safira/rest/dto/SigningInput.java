/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.dto;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.util.List;

public record SigningInput(

        @NotNull(message = "Bundle FHIR object is required")
        JsonNode bundle,

        @NotNull(message = "Provenance FHIR object is required")
        JsonNode provenance,

        @NotNull(message = "Crypto material (signerCryptoMaterial) is required")
        @Valid
        CryptoMaterialInput signerCryptoMaterial,

        @NotEmpty(message = "Certificate chain must contain at least the signer certificate")
        List<@NotBlank(message = "Certificate string cannot be blank") String> certificateChain,

        @NotNull(message = "Reference timestamp is required")
        @Min(value = 1751328000L, message = "Timestamp cannot be before 2025-07-01")
        @Max(value = 4102444800L, message = "Timestamp cannot be after 2099-12-31")
        Long referenceTimestamp,

        @NotBlank(message = "Strategy is required")
        @Pattern(regexp = "^(iat|tsa)$", message = "Strategy must be 'iat' or 'tsa'")
        String strategy,

        @NotBlank(message = "Policy identifier URI is required")
        @Pattern(
                regexp = "^https://fhir\\.saude\\.go\\.gov\\.br/r4/seguranca/ImplementationGuide/br\\.go\\.ses\\.seguranca\\|\\d+\\.\\d+\\.\\d+$",
                message = "Invalid Policy Identifier URI format. Expected: {baseUri}|{versão}"
        )
        String policyIdentifierUri
) {

    @JsonTypeInfo(
            use = JsonTypeInfo.Id.NAME,
            include = JsonTypeInfo.As.PROPERTY,
            property = "type"
    )
    @JsonSubTypes({
            @JsonSubTypes.Type(value = PemCryptoMaterial.class, name = "PEM"),
            @JsonSubTypes.Type(value = Pkcs12CryptoMaterial.class, name = "PKCS12"),
            @JsonSubTypes.Type(value = Pkcs11CryptoMaterial.class, name = "SMARTCARD"),
            @JsonSubTypes.Type(value = Pkcs11CryptoMaterial.class, name = "TOKEN"),
            @JsonSubTypes.Type(value = RemoteCryptoMaterial.class, name = "REMOTE")
    })
    public sealed interface CryptoMaterialInput permits PemCryptoMaterial, Pkcs12CryptoMaterial, Pkcs11CryptoMaterial, RemoteCryptoMaterial {}

    public record PemCryptoMaterial(
            @NotBlank(message = "PEM: Private key base64 is required") String privateKeyBase64,
            String password // Opcional
    ) implements CryptoMaterialInput {}

    public record Pkcs12CryptoMaterial(
            @NotBlank(message = "PKCS12: Content base64 is required") String contentBase64,
            @NotBlank(message = "PKCS12: Password is required") String password,
            @NotBlank(message = "PKCS12: Alias is required") String alias
    ) implements CryptoMaterialInput {}

    public record Pkcs11CryptoMaterial(
            @NotBlank(message = "PKCS11: PIN is required") String pin,
            @NotBlank(message = "PKCS11: Identifier is required") String identifier,
            @PositiveOrZero(message = "PKCS11: Slot ID must be a non-negative integer") Integer slotId, // Opcional
            @Size(max = 32, message = "PKCS11: Token label cannot exceed 32 characters") String tokenLabel // Opcional
    ) implements CryptoMaterialInput {}

    public record RemoteCryptoMaterial(
            @NotBlank(message = "REMOTE: URL is required") String remoteUrl,
            @NotBlank(message = "REMOTE: Credential is required") String credential
    ) implements CryptoMaterialInput {}
}
