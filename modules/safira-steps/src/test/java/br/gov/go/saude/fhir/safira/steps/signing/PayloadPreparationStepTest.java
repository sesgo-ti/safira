package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PayloadPreparationStepTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private PayloadPreparationStep step;

    @BeforeEach
    void setUp() {
        step = new PayloadPreparationStep();
    }

    // ===== Resultado armazenado no contexto =====

    @Test
    void shouldStorePreparedResourcesInContextAttributes() {
        String resource = "{\"resourceType\":\"Patient\",\"id\":\"p1\"}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        assertEquals(1, preparedResources(result).size());
    }

    // ===== Ordem preservada =====

    @Test
    void shouldPreserveTargetOrderFromProvenance() {
        String r1 = "{\"resourceType\":\"Patient\",\"id\":\"p1\"}";
        String r2 = "{\"resourceType\":\"Observation\",\"id\":\"obs1\"}";
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
        assertTrue(prepared.get(0).contains("\"Observation\""));
        assertTrue(prepared.get(1).contains("\"Patient\""));
    }

    // ===== Remoção de elementos não assinados =====

    @Test
    void shouldRemoveIdFromResource() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"id\":\"p1\",\"name\":\"João\"}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode prepared = MAPPER.readTree(preparedResources(result).getFirst());
        assertFalse(prepared.has("id"));
        assertEquals("João", prepared.get("name").asText());
    }

    @Test
    void shouldRemoveMetaTransientFieldsFromResource() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"meta\":{\"versionId\":\"1\",\"lastUpdated\":\"2024-01-01\",\"source\":\"http://x\",\"tag\":[{\"code\":\"T1\"}],\"profile\":[\"http://p\"]}}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode prepared = MAPPER.readTree(preparedResources(result).getFirst());
        JsonNode meta = prepared.get("meta");
        assertNotNull(meta);
        assertFalse(meta.has("versionId"));
        assertFalse(meta.has("lastUpdated"));
        assertFalse(meta.has("source"));
        assertFalse(meta.has("tag"));
        assertTrue(meta.has("profile"));
    }

    @Test
    void shouldKeepMetaProfileAndSecurityFields() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"meta\":{\"versionId\":\"2\",\"lastUpdated\":\"2024-01-01\",\"profile\":[\"http://p\"],\"security\":[{\"code\":\"N\"}]}}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode meta = MAPPER.readTree(preparedResources(result).getFirst()).get("meta");
        assertNotNull(meta);
        assertFalse(meta.has("versionId"));
        assertFalse(meta.has("lastUpdated"));
        assertTrue(meta.has("profile"));
        assertTrue(meta.has("security"));
    }

    @Test
    void shouldRemoveMetaWhenEmptyAfterStripping() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"meta\":{\"versionId\":\"1\",\"lastUpdated\":\"2024-01-01\"}}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode prepared = MAPPER.readTree(preparedResources(result).getFirst());
        assertFalse(prepared.has("meta"));
    }

    @Test
    void shouldNotModifyResourceWithoutIdOrMeta() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"name\":\"Maria\"}";
        var context = context(bundle(entry("urn:uuid:p1", resource)), provenance("urn:uuid:p1"));

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode prepared = MAPPER.readTree(preparedResources(result).getFirst());
        assertEquals("Patient", prepared.get("resourceType").asText());
        assertEquals("Maria", prepared.get("name").asText());
    }

    // ===== Falha defensiva =====

    @Test
    void shouldReturnFailureWhenTargetReferenceNotFoundInBundle() {
        Bundle bundle = Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(entry("urn:uuid:p1", "{\"resourceType\":\"Patient\"}")))
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

    private Bundle.BundleEntry entry(String fullUrl, String resource) {
        return Bundle.BundleEntry.builder()
                .fullUrl(fullUrl)
                .resource(resource)
                .build();
    }

    private Provenance provenance(String... refs) {
        return Provenance.builder()
                .resourceType("Provenance")
                .target(java.util.Arrays.stream(refs).map(this::ref).toList())
                .build();
    }

    private Reference ref(String reference) {
        return Reference.builder().reference(reference).build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    @SuppressWarnings("unchecked")
    private List<String> preparedResources(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, List.class).orElseThrow();
    }
}
