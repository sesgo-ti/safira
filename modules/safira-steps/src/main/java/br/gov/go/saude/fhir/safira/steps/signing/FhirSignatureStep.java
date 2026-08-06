/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Identifier;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Step: encapsula o JWS final como recurso FHIR {@link Signature} (passo 14 da especificação).
 *
 * <p>Extrai CPF ou CNPJ do SubjectAlternativeName do certificado do signatário (OIDs
 * 2.16.76.1.3.1 e 2.16.76.1.3.3 respectivamente) para popular {@code Signature.who.identifier}.
 */
@StepId("fhir-signature")
public class FhirSignatureStep implements SigningStep {

    private static final String CPF_OID = "2.16.76.1.3.1";
    private static final String CNPJ_OID = "2.16.76.1.3.3";

    private static final String SIG_FORMAT = "application/jose";
    private static final String TARGET_FORMAT = "application/octet-stream";
    private static final String SIG_TYPE_SYSTEM = "urn:iso-astm:E1762-95:2013";
    private static final String AUTHOR_SIGNATURE_CODE = "1.2.840.10065.1.12.1.1";

    private static final String CPF_SYSTEM = "urn:brasil:cpf";
    private static final String CNPJ_SYSTEM = "urn:brasil:cnpj";

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        String jwsFinal = context
                .getAttribute(JwsFinalStep.JWS_FINAL_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A estrutura JWS final não foi encontrada no contexto."));

        X509Certificate signerCert = context.getSignerCertificate()
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O certificado do signatário não foi encontrado no contexto."));

        SubjectIdentification identification;
        try {
            identification = extractIdentification(signerCert);
        } catch (IdentificationException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_MISSING_IDENTIFICATION,
                    e.getMessage(), context);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao extrair identificação do certificado: " + e.getMessage(), e);
        }

        Reference who = Reference.builder()
                .identifier(Identifier.builder()
                        .system(identification.system())
                        .value(identification.value())
                        .build())
                .build();

        Coding signatureType = Coding.builder()
                .system(SIG_TYPE_SYSTEM)
                .code(AUTHOR_SIGNATURE_CODE)
                .display("Author's Signature")
                .build();

        Signature signature = Signature.builder()
                .when(Instant.ofEpochSecond(context.getReferenceTimestamp()))
                .data(jwsFinal.getBytes(StandardCharsets.UTF_8))
                .sigFormat(SIG_FORMAT)
                .targetFormat(TARGET_FORMAT)
                .type(List.of(signatureType))
                .who(who)
                .build();

        SigningContext updated = context.toBuilder()
                .signature(signature)
                .build();

        return StepResult.success(getName(), updated);
    }

    private SubjectIdentification extractIdentification(X509Certificate cert) throws Exception {
        byte[] sanExtension = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (sanExtension == null) {
            throw new IdentificationException(
                    "O certificado não possui extensão SubjectAlternativeName.");
        }

        byte[] sanBytes = ASN1OctetString.getInstance(sanExtension).getOctets();
        GeneralNames sanNames = GeneralNames.getInstance(ASN1Primitive.fromByteArray(sanBytes));

        String cpf = null;
        String cnpj = null;

        for (GeneralName name : sanNames.getNames()) {
            if (name.getTagNo() != GeneralName.otherName) {
                continue;
            }
            ASN1Sequence otherName = (ASN1Sequence) name.getName();
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) otherName.getObjectAt(0);
            ASN1TaggedObject taggedValue = (ASN1TaggedObject) otherName.getObjectAt(1);
            ASN1Object rawValue = taggedValue.getBaseObject().toASN1Primitive();

            String valueString;
            if (rawValue instanceof ASN1OctetString octetString) {
                valueString = new String(octetString.getOctets(), StandardCharsets.UTF_8);
            } else if (rawValue instanceof ASN1String asn1String) {
                valueString = asn1String.getString();
            } else {
                valueString = new String(rawValue.getEncoded(ASN1Encoding.DER), StandardCharsets.UTF_8);
            }

            if (CPF_OID.equals(oid.getId())) {
                if (cpf != null) {
                    throw new IdentificationException(
                            "O certificado possui múltiplas entradas de CPF no SubjectAlternativeName.");
                }
                cpf = extractCpf(valueString);
            } else if (CNPJ_OID.equals(oid.getId())) {
                if (cnpj != null) {
                    throw new IdentificationException(
                            "O certificado possui múltiplas entradas de CNPJ no SubjectAlternativeName.");
                }
                cnpj = extractCnpj(valueString);
            }
        }

        if (cpf != null && cnpj != null) {
            throw new IdentificationException(
                    "O certificado contém CPF e CNPJ simultaneamente. Apenas um deve estar presente.");
        }
        if (cpf == null && cnpj == null) {
            throw new IdentificationException(
                    "O certificado não contém CPF (OID 2.16.76.1.3.1) nem CNPJ (OID 2.16.76.1.3.3) no SubjectAlternativeName.");
        }

        if (cpf != null) {
            return new SubjectIdentification(CPF_SYSTEM, cpf);
        }
        return new SubjectIdentification(CNPJ_SYSTEM, cnpj);
    }

    private String extractCpf(String raw) throws IdentificationException {
        // Formato ICP-Brasil: DDMMYYYY (8) + CPF (11) + outros campos
        if (raw.length() < 19) {
            throw new IdentificationException(
                    "O valor do OID 2.16.76.1.3.1 é menor que o mínimo esperado (19 caracteres).");
        }
        String cpf = raw.substring(8, 19);
        if (!cpf.matches("\\d{11}")) {
            throw new IdentificationException(
                    "O CPF extraído do certificado não contém 11 dígitos numéricos: " + cpf);
        }
        return cpf;
    }

    private String extractCnpj(String raw) throws IdentificationException {
        // Formato ICP-Brasil: CNPJ (14 dígitos) no início
        if (raw.length() < 14) {
            throw new IdentificationException(
                    "O valor do OID 2.16.76.1.3.3 é menor que o mínimo esperado (14 caracteres).");
        }
        String cnpj = raw.substring(0, 14);
        if (!cnpj.matches("\\d{14}")) {
            throw new IdentificationException(
                    "O CNPJ extraído do certificado não contém 14 dígitos numéricos: " + cnpj);
        }
        return cnpj;
    }

    private record SubjectIdentification(String system, String value) {
    }

    private static class IdentificationException extends Exception {
        IdentificationException(String message) {
            super(message);
        }
    }
}
