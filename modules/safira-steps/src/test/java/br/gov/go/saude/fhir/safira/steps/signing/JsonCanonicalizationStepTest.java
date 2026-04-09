package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonCanonicalizationStepTest {

    private JsonCanonicalizationStep step;

    @BeforeEach
    void setUp() {
        step = new JsonCanonicalizationStep();
    }

    @Test
    void shouldCanonicalizeEachPreparedResource() {
        Map<String, Object> r1 = map("resourceType", "Patient", "name", "João");
        Map<String, Object> r2 = map("resourceType", "Observation", "status", "final");
        var context = contextWith(List.of(r1, r2));

        var result = step.execute(context);

        assertSuccess(result);
        var canonicalized = canonicalizedResources(result);
        assertEquals(2, canonicalized.size());
    }

    @Test
    void shouldSortJsonKeysAlphabetically() {
        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("z_field", "last");
        resource.put("a_field", "first");
        resource.put("m_field", "middle");
        var context = contextWith(List.of(resource));

        var result = step.execute(context);

        assertSuccess(result);
        String canonicalized = canonicalizedResources(result).getFirst();
        assertEquals("{\"a_field\":\"first\",\"m_field\":\"middle\",\"z_field\":\"last\"}", canonicalized);
    }

    @Test
    void shouldPreserveOrderOfResources() {
        Map<String, Object> r1 = map("resourceType", "Patient");
        Map<String, Object> r2 = map("resourceType", "Observation");
        var context = contextWith(List.of(r1, r2));

        var result = step.execute(context);

        assertSuccess(result);
        var canonicalized = canonicalizedResources(result);
        assertTrue(canonicalized.get(0).contains("Patient"));
        assertTrue(canonicalized.get(1).contains("Observation"));
    }

    @Test
    void shouldThrowStepExceptionWhenPreparedResourcesNotFound() {
        SigningContext context = SigningContext.builder().build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(List<Map<String, Object>> preparedResources) {
        return SigningContext.builder()
                .attribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, preparedResources)
                .build();
    }

    private Map<String, Object> map(Object... pairs) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put((String) pairs[i], pairs[i + 1]);
        }
        return m;
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    @SuppressWarnings("unchecked")
    private List<String> canonicalizedResources(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(JsonCanonicalizationStep.CANONICALIZED_RESOURCES_KEY, List.class).orElseThrow();
    }
}
