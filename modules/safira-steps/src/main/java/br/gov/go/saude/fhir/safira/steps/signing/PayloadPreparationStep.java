package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@StepId("payload-preparation")
public class PayloadPreparationStep implements SigningStep {

    public static final String PREPARED_RESOURCES_KEY = "preparedResources";

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        Bundle bundle = context.getBundle();
        Provenance provenance = context.getProvenance();

        List<Map<String, Object>> preparedResources = new ArrayList<>();

        for (Reference target : provenance.target()) {
            String ref = target.reference();
            var entry = bundle.findEntryByFullUrl(ref);

            if (entry.isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                        "A instância referenciada em Provenance.target não foi encontrada no Bundle: " + ref, context);
            }

            preparedResources.add(stripUnsignedElements(entry.get().resource()));
        }

        SigningContext updated = context.toBuilder()
                .attribute(PREPARED_RESOURCES_KEY, preparedResources)
                .build();

        return StepResult.success(getName(), updated);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> stripUnsignedElements(Map<String, Object> resource) {
        Map<String, Object> copy = new LinkedHashMap<>(resource);
        copy.remove("id");

        Object metaObj = copy.get("meta");
        if (metaObj instanceof Map<?, ?> rawMeta) {
            Map<String, Object> meta = new LinkedHashMap<>((Map<String, Object>) rawMeta);
            meta.remove("versionId");
            meta.remove("lastUpdated");
            meta.remove("source");
            meta.remove("tag");
            if (meta.isEmpty()) {
                copy.remove("meta");
            } else {
                copy.put("meta", meta);
            }
        }

        return copy;
    }
}
