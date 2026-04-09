package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PayloadPreparationStepTest {

    private PayloadPreparationStep step;

    @BeforeEach
    void setUp() {
        step = new PayloadPreparationStep();
    }

    // ===== Resultado armazenado no contexto =====

    @Test
    void shouldStorePreparedResourcesInContextAttributes() {
        Map<String, Object> resource = map("resourceType", "Patient", "id", "p1");
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        var prepared = preparedResources(result);
        assertEquals(1, prepared.size());
    }

    // ===== Ordem preservada =====

    @Test
    void shouldPreserveTargetOrderFromProvenance() {
        Map<String, Object> r1 = map("resourceType", "Patient", "id", "p1");
        Map<String, Object> r2 = map("resourceType", "Observation", "id", "obs1");
        Bundle bundle = Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(entry("urn:uuid:p1", r1), entry("urn:uuid:obs1", r2)))
                .build();
        Provenance provenance = Provenance.builder()
                .resourceType("Provenance")
                .target(List.of(ref("urn:uuid:obs1"), ref("urn:uuid:p1")))
                .build();

        var result = step.execute(context(bundle, provenance));

        assertSuccess(result);
        var prepared = preparedResources(result);
        assertEquals(2, prepared.size());
        assertEquals("Observation", prepared.get(0).get("resourceType"));
        assertEquals("Patient", prepared.get(1).get("resourceType"));
    }

    // ===== Remoção de elementos não assinados =====

    @Test
    void shouldRemoveIdFromResource() {
        Map<String, Object> resource = map("resourceType", "Patient", "id", "p1", "name", "João");
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        Map<String, Object> prepared = preparedResources(result).getFirst();
        assertFalse(prepared.containsKey("id"));
        assertEquals("João", prepared.get("name"));
    }

    @Test
    void shouldRemoveMetaTransientFieldsFromResource() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("versionId", "1");
        meta.put("lastUpdated", "2024-01-01T00:00:00Z");
        meta.put("source", "http://source.example.com");
        meta.put("tag", List.of(Map.of("system", "http://tag.example", "code", "T1")));
        Map<String, Object> resource = map("resourceType", "Patient");
        resource.put("meta", meta);
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        Map<String, Object> prepared = preparedResources(result).getFirst();
        assertFalse(prepared.containsKey("meta"));
    }

    @Test
    void shouldKeepMetaProfileAndSecurityFields() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("versionId", "2");
        meta.put("lastUpdated", "2024-01-01T00:00:00Z");
        meta.put("profile", List.of("https://example.com/profile|1.0"));
        meta.put("security", List.of(Map.of("system", "http://sec.example", "code", "N")));
        Map<String, Object> resource = map("resourceType", "Patient");
        resource.put("meta", meta);
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        @SuppressWarnings("unchecked")
        Map<String, Object> preparedMeta = (Map<String, Object>) preparedResources(result).getFirst().get("meta");
        assertNotNull(preparedMeta);
        assertFalse(preparedMeta.containsKey("versionId"));
        assertFalse(preparedMeta.containsKey("lastUpdated"));
        assertTrue(preparedMeta.containsKey("profile"));
        assertTrue(preparedMeta.containsKey("security"));
    }

    @Test
    void shouldNotModifyResourceWithoutIdOrMeta() {
        Map<String, Object> resource = map("resourceType", "Patient", "name", "Maria");
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        Map<String, Object> prepared = preparedResources(result).getFirst();
        assertEquals("Patient", prepared.get("resourceType"));
        assertEquals("Maria", prepared.get("name"));
    }

    // ===== Falha defensiva =====

    @Test
    void shouldReturnFailureWhenTargetReferenceNotFoundInBundle() {
        Bundle bundle = Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(entry("urn:uuid:p1", map("resourceType", "Patient"))))
                .build();
        Provenance provenance = Provenance.builder()
                .resourceType("Provenance")
                .target(List.of(ref("urn:uuid:nao-existe")))
                .build();

        var result = step.execute(context(bundle, provenance));

        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(SignatureExceptionCode.FORMAT_TARGET_REFERENCE_MISSING,
                ((StepResult.Failure<SigningContext>) result).code());
    }

    // ===== Helpers =====

    private SigningContext context(Bundle bundle, Provenance provenance) {
        return SigningContext.builder()
                .bundle(bundle)
                .provenance(provenance)
                .build();
    }

    private Bundle bundle(Bundle.BundleEntry... entries) {
        return Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(entries))
                .build();
    }

    private Bundle.BundleEntry entry(String fullUrl, Map<String, Object> resource) {
        return Bundle.BundleEntry.builder()
                .fullUrl(fullUrl)
                .resource(resource)
                .build();
    }

    private Provenance provenance(String... refs) {
        return Provenance.builder()
                .resourceType("Provenance")
                .target(List.of(refs).stream().map(this::ref).toList())
                .build();
    }

    private Reference ref(String reference) {
        return Reference.builder().reference(reference).build();
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
    private List<Map<String, Object>> preparedResources(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, List.class).orElseThrow();
    }
}
