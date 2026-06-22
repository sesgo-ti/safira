package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.CodeableConcept;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Step: valida campos de timestamp e conformidade com a política conforme spec §6.
 *
 * <p>Para a estratégia TSA, o parsing completo do token RFC 3161 é STUB.</p>
 *
 * TODO(tsa): parse completo do token RFC 3161 (TSA.INVALID-RESPONSE quando malformado)
 * TODO(tsa): validar assinatura do token contra cadeia da TSA (TSA.VALIDATION-FAILED)
 * TODO(tsa): re-emitir consulta caso o cache esteja ausente (TSA.UNAVAILABLE)
 * TODO(tsa): garantir que o timestamp do token está dentro da validade do leaf
 *            (TEMPORAL.TSA-TIMESTAMP-OUT-OF-BOUNDS)
 */
@StepId("validation-timestamp-policy")
public class TimestampPolicyValidationStep implements ValidationStep {

    private static final String CODE_SYSTEM =
            "https://fhir.saude.go.gov.br/r4/seguranca/CodeSystem/situacao-excepcional-assinatura";
    private static final long CLOCK_SKEW_SECONDS = 300L;

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        TimestampStrategy strategy = context.getTimestampStrategy();
        if (strategy == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_TIMESTAMP_STRATEGY_INVALID,
                    "Estratégia de timestamp não definida no contexto.", context);
        }

        StepResult<ValidationContext> fail;
        ValidationContext updated = context;

        if (strategy == TimestampStrategy.IAT) {
            fail = validateIat(updated);
            if (fail != null) return fail;
        } else {
            ResolvedTsa resolved = resolveTsaStub(updated);
            if (resolved.failure != null) return resolved.failure;
            updated = resolved.context;
        }

        fail = validatePolicyCompliance(updated);
        if (fail != null) return fail;

        appendSignatureTooOldWarningIfNeeded(updated);

        return StepResult.success(getName(), updated);
    }

    private StepResult<ValidationContext> validateIat(ValidationContext context) {
        Long iat = context.getResolvedSignatureTimestamp();
        if (iat == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                    "iat ausente no contexto.", context);
        }
        long ref = context.getReferenceTimestamp();
        X509Certificate leaf = context.getSignerCertificate().orElse(null);
        if (leaf == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "Certificado do signatário ausente.", context);
        }
        long notBefore = leaf.getNotBefore().toInstant().getEpochSecond();
        long notAfter = leaf.getNotAfter().toInstant().getEpochSecond();
        if (iat < notBefore) {
            return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD,
                    "iat (" + iat + ") anterior a notBefore do certificado (" + notBefore + ").", context);
        }
        if (iat > notAfter) {
            return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD,
                    "iat (" + iat + ") posterior a notAfter do certificado (" + notAfter + ").", context);
        }
        if (iat > ref) {
            return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                    "iat (" + iat + ") indica data futura em relação ao referenceTimestamp (" + ref + ").",
                    context);
        }
        long diff = Math.abs(ref - iat);
        if (diff > CLOCK_SKEW_SECONDS) {
            context.getWarnings().add(buildWarning(
                    SignatureExceptionCode.TEMPORAL_CLOCK_SKEW_DETECTED,
                    "Diferença entre iat e referenceTimestamp = " + diff + "s (limite " + CLOCK_SKEW_SECONDS + "s)."));
        }
        return null;
    }

    private ResolvedTsa resolveTsaStub(ValidationContext context) {
        Map<String, Object> unprotected = context.getUnprotectedHeader();
        Object sigTstRaw = unprotected == null ? null : unprotected.get("sigTst");
        if (!(sigTstRaw instanceof String sigTstStr) || sigTstStr.isBlank()) {
            return ResolvedTsa.failure(StepResult.failure(getName(),
                    SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "Token TSA ausente no unprotected header.", context));
        }
        try {
            Base64.getDecoder().decode(sigTstStr);
        } catch (IllegalArgumentException ex) {
            return ResolvedTsa.failure(StepResult.failure(getName(),
                    SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "Token TSA não está em Base64 válido.", context));
        }
        long resolved = context.getReferenceTimestamp();
        ValidationContext updated = context.toBuilder()
                .resolvedSignatureTimestamp(resolved)
                .build();
        updated.getWarnings().add(buildTsaStubWarning());
        return ResolvedTsa.success(updated);
    }

    private StepResult<ValidationContext> validatePolicyCompliance(ValidationContext context) {
        Map<String, Object> protectedHeader = context.getProtectedHeader();
        Object sigPIdRaw = protectedHeader == null ? null : protectedHeader.get("sigPId");
        if (!(sigPIdRaw instanceof Map<?, ?> sigPIdMap)) {
            return StepResult.failure(getName(),
                    SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "sigPId ausente no protected header.", context);
        }
        Object idRaw = sigPIdMap.get("id");
        if (!(idRaw instanceof String idStr) || !idStr.equals(context.getPolicyIdentifierUri())) {
            return StepResult.failure(getName(),
                    SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Política da assinatura (sigPId.id=" + idRaw +
                            ") difere da política do contexto (" + context.getPolicyIdentifierUri() + ").",
                    context);
        }
        return null;
    }

    private void appendSignatureTooOldWarningIfNeeded(ValidationContext context) {
        SafiraOperationalConfigProperties opConfig = context.getOperationalConfig();
        if (opConfig == null || opConfig.validationPolicy() == null) {
            return;
        }
        Long resolved = context.getResolvedSignatureTimestamp();
        if (resolved == null) {
            return;
        }
        int thresholdDays = opConfig.validationPolicy().signatureAgeThresholdDays();
        long thresholdSeconds = (long) thresholdDays * 86_400L;
        long diff = context.getReferenceTimestamp() - resolved;
        if (diff > thresholdSeconds) {
            context.getWarnings().add(buildWarning(
                    SignatureExceptionCode.TEMPORAL_SIGNATURE_TOO_OLD,
                    "Idade da assinatura = " + diff + "s (limite " + thresholdSeconds + "s)."));
        }
    }

    private static OperationOutcome.Issue buildWarning(SignatureExceptionCode code, String diagnostics) {
        Coding coding = Coding.builder()
                .system(CODE_SYSTEM)
                .code(code.getCode())
                .display(code.getDisplay())
                .build();
        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(coding))
                .text(code.getDisplay())
                .build();
        return OperationOutcome.Issue.builder()
                .severity("warning")
                .code("business-rule")
                .details(details)
                .diagnostics(diagnostics)
                .build();
    }

    private static OperationOutcome.Issue buildTsaStubWarning() {
        Coding coding = Coding.builder()
                .system(CODE_SYSTEM)
                .code(SignatureExceptionCode.TSA.getCode())
                .display(SignatureExceptionCode.TSA.getDisplay())
                .build();
        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(coding))
                .text(SignatureExceptionCode.TSA.getDisplay())
                .build();
        return OperationOutcome.Issue.builder()
                .severity("warning")
                .code("business-rule")
                .details(details)
                .diagnostics("Validação completa do token TSA (RFC 3161) é TODO. "
                        + "Usando referenceTimestamp como aproximação.")
                .build();
    }

    private record ResolvedTsa(ValidationContext context, StepResult<ValidationContext> failure) {
        static ResolvedTsa success(ValidationContext ctx) { return new ResolvedTsa(ctx, null); }
        static ResolvedTsa failure(StepResult<ValidationContext> f) { return new ResolvedTsa(null, f); }
    }
}
