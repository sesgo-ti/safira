package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle.BundleEntry;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class PayloadIntegrityVerificationStepTest {

    private PayloadIntegrityVerificationStep step;

    @BeforeEach
    void setUp() {
        step = new PayloadIntegrityVerificationStep();
    }

    @Test
    void shouldSkipWhenBundleNull() {
        ValidationContext ctx = ValidationContext.builder()
                .provenance(simpleProvenance("urn:uuid:1"))
                .operationalConfig(defaultOpConfig())
                .build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertInstanceOf(StepResult.Success.class, result);
    }

    @Test
    void shouldSkipWhenProvenanceNull() {
        ValidationContext ctx = ValidationContext.builder()
                .bundle(simpleBundle("urn:uuid:1", "{\"resourceType\":\"Patient\"}"))
                .operationalConfig(defaultOpConfig())
                .build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertInstanceOf(StepResult.Success.class, result);
    }

    @Test
    void shouldFailWhenEntriesExceedMaxEntries() {
        Bundle bundle = Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(
                        new BundleEntry("urn:uuid:1", "{\"resourceType\":\"Patient\"}"),
                        new BundleEntry("urn:uuid:2", "{\"resourceType\":\"Patient\"}")
                ))
                .build();
        SafiraOperationalConfigProperties opConfig = new SafiraOperationalConfigProperties(
                null, null,
                new SecurityLimitsProps(1, 52428800, 10, 1L, 9_999_999_999L),
                null, null);
        ValidationContext ctx = ValidationContext.builder()
                .bundle(bundle)
                .provenance(simpleProvenance("urn:uuid:1"))
                .operationalConfig(opConfig)
                .build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED);
    }

    @Test
    void shouldFailWhenIntegrityHashMismatches() {
        String resource = "{\"resourceType\":\"Patient\",\"name\":\"John\"}";
        ValidationContext ctx = ValidationContext.builder()
                .bundle(simpleBundle("urn:uuid:1", resource))
                .provenance(simpleProvenance("urn:uuid:1"))
                .payloadBase64Url("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 43 chars wrong hash
                .operationalConfig(defaultOpConfig())
                .build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldReturnSuccessWhenHashMatches() throws Exception {
        String resource = "{\"resourceType\":\"Patient\",\"id\":\"strip-me\",\"name\":\"John\"}";
        String stripped = "{\"resourceType\":\"Patient\",\"name\":\"John\"}";
        String canonical = new JsonCanonicalizer(stripped).getEncodedString();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(baos.toByteArray());
        String b64u = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        ValidationContext ctx = ValidationContext.builder()
                .bundle(simpleBundle("urn:uuid:1", resource))
                .provenance(simpleProvenance("urn:uuid:1"))
                .payloadBase64Url(b64u)
                .operationalConfig(defaultOpConfig())
                .build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertInstanceOf(StepResult.Success.class, result);
    }

    // ===== Helpers =====

    private static Bundle simpleBundle(String fullUrl, String resourceJson) {
        return Bundle.builder()
                .resourceType("Bundle")
                .entry(List.of(new BundleEntry(fullUrl, resourceJson)))
                .build();
    }

    private static Provenance simpleProvenance(String reference) {
        return Provenance.builder()
                .resourceType("Provenance")
                .target(List.of(new Reference(reference, null, null, null)))
                .build();
    }

    private static SafiraOperationalConfigProperties defaultOpConfig() {
        return new SafiraOperationalConfigProperties(null, null,
                new SecurityLimitsProps(1000, 52428800, 10, 1L, 9_999_999_999L),
                null, null);
    }

    private static void assertFailure(StepResult<ValidationContext> result, SignatureExceptionCode expected) {
        StepResult.Failure<ValidationContext> failure = assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expected, failure.code());
    }
}
