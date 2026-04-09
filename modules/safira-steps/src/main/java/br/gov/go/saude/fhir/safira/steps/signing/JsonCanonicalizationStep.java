package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@StepId("json-canonicalizer")
public class JsonCanonicalizationStep implements SigningStep {

    public static final String CANONICALIZED_RESOURCES_KEY = "canonicalizedResources";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @SuppressWarnings("unchecked")
    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        List<Map<String, Object>> preparedResources = context
                .getAttribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, List.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                        "Os recursos preparados não foram encontrados no contexto. Verifique se o step payload-preparation foi executado."));

        try {
            List<String> canonicalized = new ArrayList<>();
            for (Map<String, Object> resource : preparedResources) {
                String json = objectMapper.writeValueAsString(resource);
                JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
                canonicalized.add(canonicalizer.getEncodedString());
            }

            SigningContext updated = context.toBuilder()
                    .attribute(CANONICALIZED_RESOURCES_KEY, canonicalized)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                    "Erro na canonicalização do JSON: " + e.getMessage(), e);
        }
    }
}
