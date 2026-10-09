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
import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.steps.dss.DssOutcomes;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code pkix-chain-validation}: etapa 2 do caso de uso de criação.
 *
 * <p>Decodifica a entrada 4 (certificado do signatário, opcionalmente com a cadeia) e delega ao
 * EU DSS ({@link CertificateValidationService}) a construção e validação do caminho no instante
 * atual: âncoras = raízes do acervo ICP-Brasil, candidatos = ACs do acervo e certificados
 * recebidos, revogação OCSP/CRL obtida pelo próprio DSS. Os certificados recebidos são apenas
 * candidatos: a confiança vem exclusivamente do acervo.
 *
 * <p>Recusa entradas com mais de {@link #MAX_CHAIN_LENGTH} certificados antes de decodificá-los.
 *
 * <p>Escreve {@code certificateChain} = caminho validado pelo DSS (folha primeiro, raiz por último).
 */
@StepId("pkix-chain-validation")
public class PkixChainValidationStep implements SigningStep {

    /** Máximo de certificados aceitos na entrada 4 (folha + ACs); caminhos ICP-Brasil têm 3 a 4 níveis. */
    public static final int MAX_CHAIN_LENGTH = 10;

    private final VerificadoresDss verifiers;
    private final CertificateValidationService validationService = new CertificateValidationService();

    public PkixChainValidationStep(VerificadoresDss verifiers) {
        this.verifiers = verifiers;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        List<String> raw = context.getRawCertificateChain();
        if (raw == null || raw.isEmpty()) {
            return fail(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE, "Nenhum certificado do signatário foi informado.", context);
        }
        if (raw.size() > MAX_CHAIN_LENGTH) {
            return fail(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                    "A cadeia informada excede o limite de " + MAX_CHAIN_LENGTH + " certificados.", context);
        }
        List<X509Certificate> certificates = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            byte[] der;
            try {
                der = Base64.getDecoder().decode(raw.get(i));
            } catch (IllegalArgumentException e) {
                return fail(SignatureExceptionCode.FORMAT_BASE64_INVALID,
                        "O certificado na posição " + i + " não está em Base64 padrão.", context);
            }
            try {
                certificates.add((X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der)));
            } catch (CertificateException | ClassCastException e) {
                return fail(SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "O certificado na posição " + i + " não é um X.509 DER válido.", context);
            }
        }

        Optional<CommonCertificateVerifier> verifier = verifiers.paraOperacao(List.of());
        if (verifier.isEmpty()) {
            return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                    "Acervo ICP-Brasil indisponível ou expirado: nenhuma âncora de confiança carregada.", context);
        }
        X509Certificate leaf = certificates.getFirst();
        CertificateReports reports = validationService.validate(leaf, certificates.subList(1, certificates.size()),
                verifier.get());
        String id = new CertificateToken(leaf).getDSSIdAsString();
        SimpleCertificateReport report = reports.getSimpleReport();
        CertificateWrapper subject = reports.getDiagnosticData().getUsedCertificateById(id);
        List<CertificateWrapper> issuers = subject.getCertificateChain();
        Indication indication = report.getCertificateIndication(id);
        if (indication != Indication.PASSED) {
            SubIndication sub = report.getCertificateSubIndication(id);
            List<CertificateWrapper> path = new ArrayList<>(List.of(subject));
            issuers.stream().filter(issuer -> !issuer.getId().equals(id)).forEach(path::add);
            return fail(DssOutcomes.code(indication, sub, path,
                    reports.getDiagnosticData().getValidationDate()), "EU DSS (certificado): " + indication
                    + (sub == null ? "" : "/" + sub) + " " + DssOutcomes.messages(report.getX509ValidationErrors(id)), context);
        }

        List<X509Certificate> chain = new ArrayList<>(List.of(leaf));
        for (CertificateWrapper issuer : issuers) {
            if (!issuer.getId().equals(id)) {
                chain.add(DSSUtils.loadCertificate(issuer.getBinaries()).getCertificate());
            }
        }
        if (chain.size() < 2 || !issuers.getLast().isTrusted()) {
            return fail(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "A cadeia deve conter ao menos o certificado do signatário e a raiz ICP-Brasil.", context);
        }
        return StepResult.success(getName(), context.toBuilder()
                .certificateChain(chain.toArray(X509Certificate[]::new))
                .build());
    }

    private StepResult<SigningContext> fail(SignatureExceptionCode code, String diagnostics, SigningContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
