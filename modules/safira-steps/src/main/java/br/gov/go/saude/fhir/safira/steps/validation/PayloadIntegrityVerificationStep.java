package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;

/**
 * Step opcional: recomputa o hash do conteúdo (Bundle + Provenance) e compara com o
 * payload assinado conforme spec §opcional.
 *
 * TODO(integrity): introduzir código dedicado para mismatch de hash; atualmente reutiliza
 *                  VALIDATION.POLICY-COMPLIANCE-FAILED.
 */
@StepId("validation-payload-integrity")
public class PayloadIntegrityVerificationStep implements ValidationStep {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) throws StepException {
        Bundle bundle = context.getBundle();
        Provenance provenance = context.getProvenance();
        if (bundle == null || provenance == null) {
            return StepResult.success(getName(), context);
        }

        SafiraOperationalConfigProperties opConfig = context.getOperationalConfig();
        SafiraOperationalConfigProperties.SecurityLimitsProps security =
                opConfig != null ? opConfig.security() : null;

        long start = System.currentTimeMillis();
        long timeoutMillis = security != null ? security.timoutVerificationBundle() * 1000L : Long.MAX_VALUE;
        int maxEntries = security != null ? security.maxEntriesBundle() : Integer.MAX_VALUE;
        long maxBytes = security != null ? security.maxBundleSize() : Long.MAX_VALUE;

        if (bundle.entry() != null && bundle.entry().size() > maxEntries) {
            return StepResult.failure(getName(),
                    SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED,
                    "Bundle possui " + bundle.entry().size() + " entradas (limite " + maxEntries + ").",
                    context);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            for (Reference target : provenance.target()) {
                if (target == null || target.reference() == null) {
                    return StepResult.failure(getName(),
                            SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                            "Referência de target ausente em Provenance.", context);
                }
                Optional<Bundle.BundleEntry> entry = bundle.findEntryByFullUrl(target.reference());
                if (entry.isEmpty()) {
                    return StepResult.failure(getName(),
                            SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                            "Recurso referenciado em Provenance.target não encontrado: " + target.reference(),
                            context);
                }
                String stripped = stripUnsignedElements(entry.get().resource());
                String canonical = new JsonCanonicalizer(stripped).getEncodedString();
                baos.write(canonical.getBytes(StandardCharsets.UTF_8));

                if (baos.size() > maxBytes) {
                    return StepResult.failure(getName(),
                            SignatureExceptionCode.SECURITY_BUNDLE_MEMORY_LIMIT_EXCEEDED,
                            "Tamanho acumulado dos recursos canonicalizados excedeu o limite de "
                                    + maxBytes + " bytes.", context);
                }
                if (System.currentTimeMillis() - start > timeoutMillis) {
                    return StepResult.failure(getName(),
                            SignatureExceptionCode.SECURITY_BUNDLE_TIMEOUT_EXCEEDED,
                            "Verificação do Bundle excedeu o tempo limite de "
                                    + (timeoutMillis / 1000) + "s.", context);
                }
            }

            byte[] hash = MessageDigest.getInstance("SHA-256").digest(baos.toByteArray());
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            if (!computed.equals(context.getPayloadBase64Url())) {
                return StepResult.failure(getName(),
                        SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                        "Hash do conteúdo não coincide com o payload assinado.", context);
            }
            return StepResult.success(getName(), context);
        } catch (StepException e) {
            throw e;
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                    "Erro ao recomputar hash do payload: " + e.getMessage(), e);
        }
    }

    private static String stripUnsignedElements(String resourceJson) throws Exception {
        ObjectNode node = (ObjectNode) MAPPER.readTree(resourceJson);
        node.remove("id");
        JsonNode metaNode = node.get("meta");
        if (metaNode != null && metaNode.isObject()) {
            ObjectNode meta = (ObjectNode) metaNode;
            meta.remove("versionId");
            meta.remove("lastUpdated");
            meta.remove("source");
            meta.remove("tag");
            if (meta.isEmpty()) {
                node.remove("meta");
            }
        }
        return MAPPER.writeValueAsString(node);
    }
}
