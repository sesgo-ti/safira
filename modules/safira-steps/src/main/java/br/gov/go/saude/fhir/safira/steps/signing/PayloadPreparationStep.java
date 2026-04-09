package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

@StepId("payload-preparation")
public class PayloadPreparationStep implements SigningStep {

    public static final String PREPARED_RESOURCES_KEY = "preparedResources";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        Bundle bundle = context.getBundle();
        Provenance provenance = context.getProvenance();

        List<String> preparedResources = new ArrayList<>();

        for (Reference target : provenance.target()) {
            String ref = target.reference();
            var entry = bundle.findEntryByFullUrl(ref);

            if (entry.isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                        "A instância referenciada em Provenance.target não foi encontrada no Bundle: " + ref, context);
            }

            try {
                String stripped = stripUnsignedElements(entry.get().resource());
                preparedResources.add(stripped);
            } catch (Exception e) {
                throw new StepException(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED,
                        "Erro ao processar recurso para assinatura: " + e.getMessage(), e);
            }
        }

        SigningContext updated = context.toBuilder()
                .attribute(PREPARED_RESOURCES_KEY, preparedResources)
                .build();

        return StepResult.success(getName(), updated);
    }

    private String stripUnsignedElements(String resourceJson) throws Exception {
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
