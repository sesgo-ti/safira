package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@StepId("jws-headers-validation")
public class JwsHeadersValidationStep implements ValidationStep {

    private static final Set<String> SUPPORTED_ALGORITHMS = Set.of("RS256", "ES256");
    private static final String SHA512_URI = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final int DIGEST_B64_LEN = 88;

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        Map<String, Object> protectedHeader = context.getProtectedHeader();
        if (protectedHeader == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Protected header ausente no contexto.", context);
        }

        StepResult<ValidationContext> fail;

        if ((fail = verifyAlg(protectedHeader, context)) != null) return fail;
        if ((fail = verifyX5c(protectedHeader, context)) != null) return fail;
        if ((fail = verifySigPId(protectedHeader, context)) != null) return fail;

        Long iatValue = null;
        Object iatRaw = protectedHeader.get("iat");
        if (iatRaw != null) {
            if (!(iatRaw instanceof Number number)) {
                return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                        "Campo 'iat' deve ser numérico.", context);
            }
            iatValue = number.longValue();
        }

        if ((fail = verifyRRefs(context.getUnprotectedHeader(), context)) != null) return fail;

        String sigTst = null;
        if (context.getUnprotectedHeader() != null) {
            Object sigTstRaw = context.getUnprotectedHeader().get("sigTst");
            if (sigTstRaw != null) {
                if (!(sigTstRaw instanceof String sigTstStr)) {
                    return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_TOKEN,
                            "Campo 'sigTst' deve ser uma string Base64.", context);
                }
                try {
                    Base64.getDecoder().decode(sigTstStr);
                } catch (IllegalArgumentException ex) {
                    return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_TOKEN,
                            "Campo 'sigTst' não está em Base64 válido.", context);
                }
                sigTst = sigTstStr;
            }
        }

        TimestampStrategy strategy;
        Long resolvedTimestamp = null;
        boolean hasIat = iatValue != null;
        boolean hasSigTst = sigTst != null;

        if (hasIat && !hasSigTst) {
            strategy = TimestampStrategy.IAT;
            resolvedTimestamp = iatValue;
        } else if (!hasIat && hasSigTst) {
            strategy = TimestampStrategy.TSA;
        } else {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_TIMESTAMP_STRATEGY_INVALID,
                    "Estratégia de timestamp inválida: deve conter apenas 'iat' ou apenas 'sigTst'.", context);
        }

        ValidationContext updated = context.toBuilder()
                .timestampStrategy(strategy)
                .resolvedSignatureTimestamp(resolvedTimestamp)
                .build();

        return StepResult.success(getName(), updated);
    }

    private StepResult<ValidationContext> verifyAlg(Map<String, Object> header, ValidationContext context) {
        Object alg = header.get("alg");
        if (alg == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM,
                    "Campo 'alg' ausente no protected header.", context);
        }
        if (!(alg instanceof String algStr) || !SUPPORTED_ALGORITHMS.contains(algStr)) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM,
                    "Algoritmo de assinatura não suportado: " + alg, context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyX5c(Map<String, Object> header, ValidationContext context) {
        Object x5c = header.get("x5c");
        if (!(x5c instanceof List<?> list) || list.isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                    "Campo 'x5c' ausente ou vazio.", context);
        }
        for (Object element : list) {
            if (!(element instanceof String)) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "Entradas de 'x5c' devem ser strings.", context);
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private StepResult<ValidationContext> verifySigPId(Map<String, Object> header, ValidationContext context) {
        Object sigPId = header.get("sigPId");
        if (!(sigPId instanceof Map<?, ?> sigPIdMap)) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED,
                    "Campo 'sigPId' ausente ou inválido no protected header.", context);
        }
        Object id = ((Map<String, Object>) sigPIdMap).get("id");
        if (!(id instanceof String idStr) || idStr.isBlank()) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED,
                    "Campo 'sigPId.id' ausente ou inválido.", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyRRefs(Map<String, Object> unprotectedHeader, ValidationContext context) {
        if (unprotectedHeader == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                    "Unprotected header ausente; evidências LTV (rRefs) obrigatórias.", context);
        }
        Object rRefs = unprotectedHeader.get("rRefs");
        if (!(rRefs instanceof Map<?, ?> rRefsMap)) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                    "Campo 'rRefs' ausente ou inválido.", context);
        }

        Set<String> ocspDigests = new HashSet<>();
        Set<String> crlDigests = new HashSet<>();

        StepResult<ValidationContext> fail;
        if ((fail = validateRefList(rRefsMap.get("ocspRefs"), ocspDigests, context)) != null) return fail;
        if ((fail = validateRefList(rRefsMap.get("crlRefs"), crlDigests, context)) != null) return fail;

        for (String digest : ocspDigests) {
            if (crlDigests.contains(digest)) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Digest duplicado entre ocspRefs e crlRefs.", context);
            }
        }
        return null;
    }

    private StepResult<ValidationContext> validateRefList(Object listObj, Set<String> digestCollector, ValidationContext context) {
        if (listObj == null) {
            return null;
        }
        if (!(listObj instanceof List<?> list)) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                    "Referências LTV devem ser arrays.", context);
        }
        for (Object entry : list) {
            if (!(entry instanceof Map<?, ?> map)) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Entrada de referência LTV inválida.", context);
            }
            Object digestAlg = map.get("digestAlg");
            Object digestValue = map.get("digestValue");
            if (!(digestAlg instanceof String alg) || !(digestValue instanceof String value)) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Entrada LTV deve conter digestAlg e digestValue.", context);
            }
            if (!SHA512_URI.equals(alg)) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Algoritmo de digest LTV inválido: " + alg, context);
            }
            if (value.length() != DIGEST_B64_LEN) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Tamanho do digest LTV inválido.", context);
            }
            try {
                Base64.getDecoder().decode(value);
            } catch (IllegalArgumentException ex) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "digestValue LTV não está em Base64 válido.", context);
            }
            if (!digestCollector.add(value)) {
                return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID,
                        "Digest LTV duplicado na mesma lista.", context);
            }
        }
        return null;
    }
}
