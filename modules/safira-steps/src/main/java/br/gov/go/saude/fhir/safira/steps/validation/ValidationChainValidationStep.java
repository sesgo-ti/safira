/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.CodeableConcept;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.List;

/**
 * Step: valida a cadeia de certificados reconstruída pelo passo
 * {@code validation-chain-build} conforme spec §3.2–3.8.
 */
@StepId("validation-chain-validation")
public class ValidationChainValidationStep implements ValidationStep {

    private static final String ICP_BRASIL_OID_PREFIX = "2.16.76.1";
    private static final String CERTIFICATE_POLICIES_EXT_OID = Extension.certificatePolicies.getId();
    private static final String CODE_SYSTEM =
            "https://fhir.saude.go.gov.br/r4/seguranca/CodeSystem/situacao-excepcional-assinatura";

    private final TrustStoreService trustStoreService;

    public ValidationChainValidationStep(TrustStoreService trustStoreService) {
        this.trustStoreService = trustStoreService;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        List<X509Certificate> chain = context.getCertificateChain().orElse(List.of());

        // §3.2 estrutura: pelo menos 2 certificados
        if (chain.size() < 2) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "Cadeia de certificados deve conter pelo menos 2 elementos (leaf e raiz).", context);
        }

        SafiraOperationalConfigProperties opConfig = context.getOperationalConfig();
        SafiraOperationalConfigProperties.TrustStoreProps trustStore = opConfig.trustStore();
        X509Certificate leaf = chain.get(0);
        X509Certificate root = chain.get(chain.size() - 1);
        long refTs = context.getReferenceTimestamp();

        // §3.3 raiz ICP-Brasil confiável
        if (!trustStoreService.isTrustedRoot(root)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_TRUSTED_ROOT,
                    "Raiz da cadeia não pertence à lista confiável de ACs ICP-Brasil.", context);
        }

        // §3.4 elegibilidade ICP-Brasil: folha deve ter política 2.16.76.1.*
        if (!hasIcpBrasilPolicy(leaf)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "Certificado do signatário não possui política ICP-Brasil (OID " +
                            ICP_BRASIL_OID_PREFIX + ").", context);
        }

        // §3.5 data mínima: leaf.notBefore ≥ minimumCertificateDate
        long minDate = trustStore.minimumCertificateDate();
        long leafNotBefore = leaf.getNotBefore().toInstant().getEpochSecond();
        if (leafNotBefore < minDate) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD,
                    "Certificado do signatário foi emitido antes da data mínima exigida.", context);
        }

        // §3.6 validade temporal de cada cert
        for (X509Certificate cert : chain) {
            long nb = cert.getNotBefore().toInstant().getEpochSecond();
            long na = cert.getNotAfter().toInstant().getEpochSecond();
            String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
            if (refTs < nb) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_YET_VALID,
                        "Certificado [" + subject + "] ainda não era válido no timestamp de referência.", context);
            }
            if (refTs > na) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_EXPIRED,
                        "Certificado [" + subject + "] estava expirado no timestamp de referência.", context);
            }
        }

        // §3.7 hierarquia (i de 0 a n-2): cert[i] assinado por cert[i+1]; issuer/subject match
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate child = chain.get(i);
            X509Certificate parent = chain.get(i + 1);
            if (!child.getIssuerX500Principal().equals(parent.getSubjectX500Principal())) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                        "Issuer do certificado na posição " + i +
                                " não corresponde ao subject do certificado na posição " + (i + 1) + ".", context);
            }
            try {
                child.verify(parent.getPublicKey());
            } catch (Exception e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                        "Falha na verificação criptográfica da assinatura do certificado " +
                                "na posição " + i + ": " + e.getMessage(), context);
            }
        }

        // §3.8 algoritmo e tamanho de chave
        for (X509Certificate cert : chain) {
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey rsa) {
                int bits = rsa.getModulus().bitLength();
                if (bits < 2048) {
                    return StepResult.failure(getName(), SignatureExceptionCode.CERT_WEAK_KEY,
                            "Chave RSA com " + bits + " bits é inferior ao mínimo exigido (2048).", context);
                }
            } else if (pk instanceof ECPublicKey ec) {
                ECParameterSpec params = ec.getParams();
                int fieldSize = params.getCurve().getField().getFieldSize();
                if (fieldSize != 256) {
                    return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                            "Curva EC não suportada: field size " + fieldSize + " (esperado P-256).", context);
                }
            } else {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                        "Algoritmo de chave pública não suportado: " + pk.getAlgorithm(), context);
            }
        }

        // Warnings: CERT.NEAR-EXPIRY
        int thresholdDays = opConfig.validationPolicy() != null
                ? opConfig.validationPolicy().nearExpiryThresholdDays()
                : 30;
        long thresholdSeconds = (long) thresholdDays * 86_400L;
        for (X509Certificate cert : chain) {
            long na = cert.getNotAfter().toInstant().getEpochSecond();
            long remaining = na - refTs;
            if (remaining >= 0 && remaining < thresholdSeconds) {
                String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
                long days = remaining / 86_400L;
                context.getWarnings().add(buildNearExpiryWarning(subject, days));
            }
        }

        return StepResult.success(getName(), context);
    }

    private static boolean hasIcpBrasilPolicy(X509Certificate leaf) {
        byte[] extValue = leaf.getExtensionValue(CERTIFICATE_POLICIES_EXT_OID);
        if (extValue == null) {
            return false;
        }
        try (ASN1InputStream outer = new ASN1InputStream(new ByteArrayInputStream(extValue))) {
            byte[] raw = ((org.bouncycastle.asn1.ASN1OctetString) outer.readObject()).getOctets();
            try (ASN1InputStream inner = new ASN1InputStream(new ByteArrayInputStream(raw))) {
                ASN1Sequence seq = (ASN1Sequence) inner.readObject();
                CertificatePolicies policies = CertificatePolicies.getInstance(seq);
                for (PolicyInformation pi : policies.getPolicyInformation()) {
                    String oid = pi.getPolicyIdentifier().getId();
                    if (oid.startsWith(ICP_BRASIL_OID_PREFIX)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    private static OperationOutcome.Issue buildNearExpiryWarning(String subject, long daysRemaining) {
        Coding coding = Coding.builder()
                .system(CODE_SYSTEM)
                .code(SignatureExceptionCode.CERT_NEAR_EXPIRY.getCode())
                .display(SignatureExceptionCode.CERT_NEAR_EXPIRY.getDisplay())
                .build();
        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(coding))
                .text(SignatureExceptionCode.CERT_NEAR_EXPIRY.getDisplay())
                .build();
        return OperationOutcome.Issue.builder()
                .severity("warning")
                .code("business-rule")
                .details(details)
                .diagnostics("Certificado próximo da expiração: " + subject +
                        ", dias restantes=" + daysRemaining)
                .build();
    }
}
