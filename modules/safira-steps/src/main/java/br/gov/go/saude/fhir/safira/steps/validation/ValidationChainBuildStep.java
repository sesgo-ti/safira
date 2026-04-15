package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Step: decodifica cada entrada da cabeçalho {@code x5c} do protected header
 * em {@link X509Certificate} DER e popula {@code context.certificateChain}.
 *
 * <p>Spec §3.1 — Construção da cadeia de certificados.
 */
@StepId("validation-chain-build")
public class ValidationChainBuildStep implements ValidationStep {

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        Map<String, Object> protectedHeader = context.getProtectedHeader();
        if (protectedHeader == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "Protected header ausente ao construir a cadeia de certificados.", context);
        }

        Object x5cObj = protectedHeader.get("x5c");
        if (!(x5cObj instanceof List<?> x5c) || x5c.isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "Campo 'x5c' ausente ou vazio no protected header.", context);
        }

        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "CertificateFactory X.509 indisponível: " + e.getMessage(), context);
        }

        List<X509Certificate> chain = new ArrayList<>(x5c.size());
        for (int i = 0; i < x5c.size(); i++) {
            Object entry = x5c.get(i);
            if (!(entry instanceof String entryStr)) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "x5c[" + i + "] não é uma string Base64.", context);
            }

            byte[] der;
            try {
                der = Base64.getDecoder().decode(entryStr);
            } catch (IllegalArgumentException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                        "x5c[" + i + "] não está em Base64 válido.", context);
            }

            try {
                X509Certificate cert = (X509Certificate)
                        cf.generateCertificate(new ByteArrayInputStream(der));
                chain.add(cert);
            } catch (CertificateException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "x5c[" + i + "] não é um certificado X.509 DER válido.", context);
            }
        }

        return StepResult.success(getName(),
                context.toBuilder().certificateChain(chain).build());
    }
}
