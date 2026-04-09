package br.gov.go.saude.fhir.safira.steps.signing.revocation;

/**
 * Evidência de revogação para validação de longo prazo (LTV).
 * Armazenada no {@code SigningContext.attributes} com chave {@code "revocationEvidences"}
 * como {@code List<RevocationEvidence>} para inclusão posterior no unprotected header JWS (rRefs).
 *
 * @param source            fonte da evidência: "OCSP" ou "CRL"
 * @param responseDerBase64 resposta completa no formato DER codificada em Base64
 * @param hashSha512        hash SHA-512 da resposta DER em hexadecimal
 */
public record RevocationEvidence(
        String source,
        String responseDerBase64,
        String hashSha512
) {}