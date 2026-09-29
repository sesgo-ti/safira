/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Elegibilidade e identidade do certificado folha ICP-Brasil (política 0.2.0: C16, C18, C19;
 * criar 2.5/2.6; validar 4.1).
 *
 * <p>Complementa — não substitui — a validação PKIX do caminho, feita pela lib
 * icpbrasil-truststore. Os códigos retornados são os do caso de uso de criação; a validação
 * reinterpreta os que o IG define de forma diferente.
 */
public final class IcpBrasilCertificateProfile {

    private static final String ANY_POLICY = "2.5.29.32.0";
    private static final String ICP_BRASIL_CERT_POLICY_BRANCH = "2.16.76.1.2.";
    private static final String SAN_CPF_OID = "2.16.76.1.3.1";
    private static final String SAN_CNPJ_OID = "2.16.76.1.3.3";
    private static final int KEY_USAGE_DIGITAL_SIGNATURE = 0;

    private IcpBrasilCertificateProfile() {
    }

    /**
     * @param leaf             certificado folha (titular)
     * @param issuer           emissor imediato da folha (base do {@code issuerSha256})
     * @param allowlist        {@code acceptedCertificatePolicies}
     * @param minCertIssueDate {@code temporalPolicy.minCertIssueDate} (epoch seconds)
     */
    public static ProfileResult evaluate(X509Certificate leaf, X509Certificate issuer,
                                         List<AcceptedCertificatePolicy> allowlist, long minCertIssueDate) {
        List<String> policies = certificatePolicies(leaf);
        List<String> accepted = policies.stream()
                .filter(oid -> oid.startsWith(ICP_BRASIL_CERT_POLICY_BRANCH))
                .filter(oid -> typeOf(oid).isPresent())
                .toList();
        if (policies.contains(ANY_POLICY) || accepted.isEmpty()) {
            return rejected(SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "O certificado folha não declara política ICP-Brasil A3, A4, SE-S ou SE-H (anyPolicy não é aceito).");
        }
        if (accepted.size() > 1) {
            return rejected(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                    "O certificado folha declara mais de uma política ICP-Brasil aceitável: " + accepted);
        }
        String policyOid = accepted.getFirst();
        String issuerSha256 = sha256Hex(issuer);
        List<AcceptedCertificatePolicy> matches = allowlist.stream()
                .filter(entry -> policyOid.equals(entry.oid()) && issuerSha256.equals(entry.issuerSha256()))
                .toList();
        if (matches.isEmpty()) {
            return rejected(SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "A política " + policyOid + " não consta da allowlist para o emissor " + issuerSha256 + ".");
        }
        CertificateType type = matches.getFirst().type();
        if (matches.size() > 1 || !type.matchesBranch(policyOid)) {
            return rejected(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                    "Correspondência ambígua ou incoerente entre a política " + policyOid + " e a allowlist.");
        }

        if (!(leaf.getPublicKey() instanceof RSAPublicKey rsa)) {
            return rejected(SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                    "A chave do certificado folha não é RSA: " + leaf.getPublicKey().getAlgorithm());
        }
        int bits = rsa.getModulus().bitLength();
        if (!type.allowedRsaSizes().contains(bits)) {
            return rejected(SignatureExceptionCode.CERT_WEAK_KEY,
                    "Chave RSA de " + bits + " bits não admitida para certificado " + type.label()
                            + " (admitidos: " + type.allowedRsaSizes() + ").");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null || keyUsage.length <= KEY_USAGE_DIGITAL_SIGNATURE || !keyUsage[KEY_USAGE_DIGITAL_SIGNATURE]) {
            return rejected(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                    "A extensão KeyUsage do certificado folha não declara digitalSignature.");
        }
        if (leaf.getBasicConstraints() >= 0) {
            return rejected(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                    "O certificado folha não pode ser de AC (BasicConstraints cA=true).");
        }
        if (leaf.getNotBefore().toInstant().getEpochSecond() < minCertIssueDate) {
            return rejected(SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD,
                    "O certificado folha foi emitido antes da data mínima exigida (temporalPolicy.minCertIssueDate).");
        }
        return identity(leaf, type)
                .<ProfileResult>map(id -> new ProfileResult.Eligible(id, policyOid))
                .orElseGet(() -> rejected(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION,
                        "Identificação do titular (" + (type.isNaturalPerson() ? "CPF" : "CNPJ")
                                + ") ausente, inválida, ambígua ou divergente entre subject.serialNumber e SAN."));
    }

    public static boolean isValidCpf(String digits) {
        if (digits == null || !digits.matches("\\d{11}") || digits.chars().distinct().count() == 1) {
            return false;
        }
        return checkDigit(digits, 9, 10) == digits.charAt(9) - '0'
                && checkDigit(digits, 10, 11) == digits.charAt(10) - '0';
    }

    public static boolean isValidCnpj(String digits) {
        if (digits == null || !digits.matches("\\d{14}") || digits.chars().distinct().count() == 1) {
            return false;
        }
        int[] first = {5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        int[] second = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        return cnpjDigit(digits, first) == digits.charAt(12) - '0'
                && cnpjDigit(digits, second) == digits.charAt(13) - '0';
    }

    public static String sha256Hex(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Falha ao calcular SHA-256 do certificado", e);
        }
    }

    private static Optional<CertificateType> typeOf(String oid) {
        for (CertificateType type : CertificateType.values()) {
            if (type.matchesBranch(oid)) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    private static Optional<SignerIdentity> identity(X509Certificate leaf, CertificateType type) {
        int length = type.isNaturalPerson() ? 11 : 14;
        List<String> values = new ArrayList<>();
        Optional<String> serial = subjectSerialNumber(leaf);
        if (serial.isPresent()) {
            String digits = serial.get().replaceAll("[.\\-/]", "");
            if (!digits.matches("\\d{" + length + "}")) {
                return Optional.empty();
            }
            values.add(digits);
        }
        SanIdentities san = sanIdentities(leaf);
        if (san == null) {
            return Optional.empty();
        }
        if (type.isNaturalPerson()) {
            if (!san.cnpj().isEmpty()) {
                return Optional.empty();
            }
            values.addAll(san.cpf());
        } else {
            values.addAll(san.cnpj());
        }
        if (values.isEmpty() || values.stream().distinct().count() != 1) {
            return Optional.empty();
        }
        String value = values.getFirst();
        boolean valid = type.isNaturalPerson() ? isValidCpf(value) : isValidCnpj(value);
        if (!valid) {
            return Optional.empty();
        }
        return Optional.of(new SignerIdentity(type,
                type.isNaturalPerson() ? SignerIdentity.CPF_SYSTEM : SignerIdentity.CNPJ_SYSTEM, value));
    }

    private static Optional<String> subjectSerialNumber(X509Certificate leaf) {
        X500Name subject = X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded());
        RDN[] rdns = subject.getRDNs(BCStyle.SERIALNUMBER);
        if (rdns.length == 0) {
            return Optional.empty();
        }
        return Optional.of(IETFUtils.valueToString(rdns[0].getFirst().getValue()));
    }

    private record SanIdentities(List<String> cpf, List<String> cnpj) {
    }

    /** CPF/CNPJ nos otherName ICP-Brasil; nulo se o SAN for malformado ou um valor for ilegível. */
    private static SanIdentities sanIdentities(X509Certificate leaf) {
        List<String> cpf = new ArrayList<>();
        List<String> cnpj = new ArrayList<>();
        byte[] extension = leaf.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (extension == null) {
            return new SanIdentities(cpf, cnpj);
        }
        try {
            GeneralNames names = GeneralNames.getInstance(
                    ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extension).getOctets()));
            for (GeneralName name : names.getNames()) {
                if (name.getTagNo() != GeneralName.otherName) {
                    continue;
                }
                ASN1Sequence otherName = ASN1Sequence.getInstance(name.getName());
                String oid = ASN1ObjectIdentifier.getInstance(otherName.getObjectAt(0)).getId();
                if (!SAN_CPF_OID.equals(oid) && !SAN_CNPJ_OID.equals(oid)) {
                    continue;
                }
                String raw = otherNameValue(ASN1TaggedObject.getInstance(otherName.getObjectAt(1)));
                if (SAN_CPF_OID.equals(oid)) {
                    // Layout ICP-Brasil: data de nascimento DDMMAAAA (8) seguida do CPF (11)
                    if (raw.length() < 19) {
                        return null;
                    }
                    cpf.add(raw.substring(8, 19));
                } else {
                    if (raw.length() < 14) {
                        return null;
                    }
                    cnpj.add(raw.substring(0, 14));
                }
            }
            return new SanIdentities(cpf, cnpj);
        } catch (Exception e) {
            return null;
        }
    }

    private static String otherNameValue(ASN1TaggedObject tagged) throws IOException {
        ASN1Primitive value = tagged.getBaseObject().toASN1Primitive();
        if (value instanceof ASN1OctetString octets) {
            return new String(octets.getOctets(), StandardCharsets.ISO_8859_1);
        }
        if (value instanceof ASN1String string) {
            return string.getString();
        }
        return new String(value.getEncoded(ASN1Encoding.DER), StandardCharsets.ISO_8859_1);
    }

    private static List<String> certificatePolicies(X509Certificate leaf) {
        byte[] extension = leaf.getExtensionValue(Extension.certificatePolicies.getId());
        if (extension == null) {
            return List.of();
        }
        try {
            CertificatePolicies policies = CertificatePolicies.getInstance(
                    ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extension).getOctets()));
            List<String> oids = new ArrayList<>();
            for (PolicyInformation info : policies.getPolicyInformation()) {
                oids.add(info.getPolicyIdentifier().getId());
            }
            return oids;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static int checkDigit(String digits, int count, int weightStart) {
        int sum = 0;
        for (int i = 0; i < count; i++) {
            sum += (digits.charAt(i) - '0') * (weightStart - i);
        }
        int remainder = (sum * 10) % 11;
        return remainder == 10 ? 0 : remainder;
    }

    private static int cnpjDigit(String digits, int[] weights) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) {
            sum += (digits.charAt(i) - '0') * weights[i];
        }
        int remainder = sum % 11;
        return remainder < 2 ? 0 : 11 - remainder;
    }

    private static ProfileResult rejected(SignatureExceptionCode code, String diagnostics) {
        return new ProfileResult.Rejected(code, diagnostics);
    }
}
