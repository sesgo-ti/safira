/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.revocation.RevocationEvidence;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation.RevocationService;

import javax.security.auth.x500.X500Principal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Step: Valida a cadeia de certificados já montada pelo step {@code chain-build}.
 *
 * <p>Verificações realizadas em ordem:
 * <ol>
 *   <li>2.2 Verifique se a cadeia possui pelo menos 2 certificados</li>
 *   <li>2.4 Raiz ICP-Brasil confiável (último certificado)</li>
 *   <li>2.5 Elegibilidade ICP-Brasil: política 2.16.76.1 no certificado folha</li>
 *   <li>Key Usage: digitalSignature e nonRepudiation obrigatórios</li>
 *   <li>2.6 Data mínima de emissão e validade temporal do signatário</li>
 *   <li>2.7 Validação criptográfica, hierárquica e temporal de cada elo da cadeia</li>
 *   <li>2.8 Verificação de revogação via OCSP (preferencial) / CRL (fallback)</li>
 * </ol>
 *
 * <p>Em caso de sucesso, o atributo {@code "revocationEvidences"} ({@code List<RevocationEvidence>})
 * é adicionado ao contexto para LTV.
 */
@StepId("chain-validation")
public class ChainValidationStep implements SigningStep {

    static final String REVOCATION_EVIDENCES_KEY = "revocationEvidences";

    private final TrustStoreService trustStoreService;
    private final RevocationService revocationService;

    public ChainValidationStep(TrustStoreService trustStoreService,
                               RevocationService revocationService) {
        this.trustStoreService = trustStoreService;
        this.revocationService = revocationService;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        X509Certificate[] certArray = context.getCertificateChain().orElse(null);

        // 2.2 Pelo menos 2 certificados
        if (certArray == null || certArray.length < 2) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "A cadeia de certificados deve conter pelo menos 2 certificados: " +
                            "o certificado do signatário (posição 0) e a raiz ICP-Brasil (última posição).", context);
        }

        List<X509Certificate> certs = Arrays.asList(certArray);

        // 2.4 Validação da raiz ICP-Brasil
        X509Certificate rootCert = certs.getLast();
        if (!CertificateParser.isSelfSigned(rootCert)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_TRUSTED_ROOT,
                    "O último certificado da cadeia não é auto-assinado e, portanto, não pode ser uma AC-Raiz ICP-Brasil.", context);
        }
        if (!trustStoreService.isTrustedRoot(rootCert)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_TRUSTED_ROOT,
                    "O certificado raiz da cadeia fornecida não corresponde a nenhum certificado raiz ICP-Brasil confiável.", context);
        }

        // 2.5 Verificação de elegibilidade ICP-Brasil (certificado folha, posição 0)
        X509Certificate leafCert = certs.getFirst();
        List<String> policies;
        try {
            policies = CertificateParser.getCertificatePolicies(leafCert);
        } catch (IllegalArgumentException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "O certificado do signatário não contém a extensão Certificate Policies (OID 2.5.29.32).", context);
        }
        boolean hasIcpBrasilPolicy = policies.stream().anyMatch(oid -> oid.startsWith("2.16.76.1"));
        if (!hasIcpBrasilPolicy) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "O certificado do signatário não possui política ICP-Brasil (OID iniciado por 2.16.76.1). " +
                            "Certificado não elegível para assinatura digital avançada.", context);
        }

        // Verificação Key Usage: digitalSignature (bit 0) e nonRepudiation (bit 1) obrigatórios
        boolean[] keyUsage;
        try {
            keyUsage = CertificateParser.getKeyUsage(leafCert);
        } catch (IllegalArgumentException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "O certificado do signatário não contém a extensão Key Usage (OID 2.5.29.15).", context);
        }
        if (keyUsage.length < 2 || !keyUsage[0] || !keyUsage[1]) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "O certificado do signatário não possui os bits digitalSignature (posição 0) e " +
                            "nonRepudiation (posição 1) marcados como obrigatórios na extensão Key Usage.", context);
        }

        // 2.6 Verificação de data mínima e validade temporal do signatário
        long refTs = context.getReferenceTimestamp();
        long minDate = context.getOperationalConfig().trustStore().minimumCertificateDate();
        StepResult<SigningContext> fail = validateSignerCertDates(leafCert, refTs, minDate, context);
        if (fail != null) return fail;

        // 2.7 Validação da cadeia (posição i de 0 a n-2)
        for (int i = 0; i < certs.size() - 1; i++) {
            X509Certificate certI = certs.get(i);
            X509Certificate certINext = certs.get(i + 1);

            // 2.7.1 Validação criptográfica: assinatura de certI verificada com chave pública de certI+1
            try {
                certI.verify(certINext.getPublicKey());
            } catch (Exception e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                        "Falha na verificação criptográfica: a assinatura do certificado [" +
                                certI.getSubjectX500Principal().getName() + "] (posição " + i +
                                ") não pôde ser verificada com a chave pública do certificado [" +
                                certINext.getSubjectX500Principal().getName() + "] (posição " + (i + 1) + ").", context);
            }

            // 2.7.2 Validação hierárquica: issuer(certI) == subject(certI+1)
            if (!certI.getIssuerX500Principal().equals(certINext.getSubjectX500Principal())) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                        "Falha na hierarquia da cadeia: o issuer do certificado [" +
                                certI.getSubjectX500Principal().getName() + "] (posição " + i + ") é [" +
                                certI.getIssuerX500Principal().getName() +
                                "], mas o subject do certificado na posição " + (i + 1) + " é [" +
                                certINext.getSubjectX500Principal().getName() + "].", context);
            }

            // 2.7.3 Validação temporal: notBefore ≤ refTs ≤ notAfter
            fail = validateCertTemporal(certI, refTs, context);
            if (fail != null) return fail;
        }

        // 2.8 Validação de revogação (posição i de 0 a n-2)
        List<RevocationEvidence> evidences = new ArrayList<>();
        for (int i = 0; i < certs.size() - 1; i++) {
            fail = checkRevocation(certs.get(i), certs.get(i + 1), evidences, context);
            if (fail != null) return fail;
        }

        return StepResult.success(getName(), context.toBuilder()
                .attribute(REVOCATION_EVIDENCES_KEY, List.copyOf(evidences))
                .build());
    }

    private StepResult<SigningContext> validateSignerCertDates(X509Certificate cert, long refTs,
                                                               long minDate, SigningContext context) {
        long notBeforeEpoch = cert.getNotBefore().toInstant().getEpochSecond();
        long notAfterEpoch = cert.getNotAfter().toInstant().getEpochSecond();

        if (notBeforeEpoch < minDate) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD,
                    "O certificado do signatário foi emitido antes da data mínima exigida pela política " +
                            "de segurança vigente. Certificados ICP-Brasil devem ser emitidos a partir de " +
                            "2025-07-01 para conformidade com os requisitos criptográficos atuais.", context);
        }
        if (refTs < notBeforeEpoch) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_YET_VALID,
                    "O certificado do signatário ainda não estava válido no momento do timestamp de " +
                            "referência fornecido (notBefore > timestamp de referência).", context);
        }
        if (refTs > notAfterEpoch) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_EXPIRED,
                    "O certificado do signatário estava expirado no momento do timestamp de " +
                            "referência fornecido (timestamp de referência > notAfter).", context);
        }
        return null;
    }

    private StepResult<SigningContext> validateCertTemporal(X509Certificate cert, long refTs,
                                                            SigningContext context) {
        long notBeforeEpoch = cert.getNotBefore().toInstant().getEpochSecond();
        long notAfterEpoch = cert.getNotAfter().toInstant().getEpochSecond();
        String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);

        if (refTs < notBeforeEpoch) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_NOT_YET_VALID,
                    "O certificado [" + subject + "] ainda não estava válido no momento " +
                            "do timestamp de referência fornecido.", context);
        }
        if (refTs > notAfterEpoch) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_EXPIRED,
                    "O certificado [" + subject + "] estava expirado no momento " +
                            "do timestamp de referência fornecido.", context);
        }
        return null;
    }

    private StepResult<SigningContext> checkRevocation(X509Certificate cert, X509Certificate issuer,
                                                       List<RevocationEvidence> evidences,
                                                       SigningContext context) {
        RevocationStatus result = revocationService.check(cert, issuer);
        String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
        return switch (result) {
            case RevocationStatus.Good g -> {
                if (g.responseDer() != null) {
                    evidences.add(new RevocationEvidence(
                            g.source(),
                            Base64.getEncoder().encodeToString(g.responseDer()),
                            sha512Hex(g.responseDer())
                    ));
                }
                yield null;
            }
            case RevocationStatus.Revoked r -> StepResult.failure(getName(),
                    SignatureExceptionCode.CERT_REVOKED,
                    "O certificado [" + subject + "] foi revogado. Fonte: " + r.source() + ".", context);
            case RevocationStatus.NoDistributionPoints ignored -> StepResult.failure(getName(),
                    SignatureExceptionCode.REVOCATION_NO_DISTRIBUTION_POINTS,
                    "O certificado [" + subject + "] não contém pontos de distribuição de " +
                            "revogação válidos nas extensões AIA (OCSP) ou CDP (CRL).", context);
            case RevocationStatus.OcspUnavailable ignored -> StepResult.failure(getName(),
                    SignatureExceptionCode.REVOCATION_OCSP_UNAVAILABLE,
                    "O serviço OCSP está inacessível ao verificar a revogação do certificado [" + subject + "].", context);
            case RevocationStatus.CrlUnavailable ignored -> StepResult.failure(getName(),
                    SignatureExceptionCode.REVOCATION_CRL_UNAVAILABLE,
                    "A lista CRL está inacessível ao verificar a revogação do certificado [" + subject + "].", context);
            case RevocationStatus.NoConnectivity ignored -> StepResult.failure(getName(),
                    SignatureExceptionCode.REVOCATION_NO_CONNECTIVITY,
                    "Sem conectividade externa para verificar a revogação do certificado [" + subject + "].", context);
            case RevocationStatus.Malformed m -> StepResult.failure(getName(),
                    SignatureExceptionCode.REVOCATION_RESPONSE_MALFORMED,
                    "A resposta de revogação está malformada ao verificar o certificado [" + subject + "]. Fonte: " + m.source() + ".", context);
        };
    }

    private String sha512Hex(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-512").digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
}
