package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

@StepId("content-digest")
public class ContentDigestStep implements SigningStep {

    public static final String CONTENT_DIGEST_KEY = "contentDigest";

    @SuppressWarnings("unchecked")
    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        List<String> canonicalizedResources = context
                .getAttribute(JsonCanonicalizationStep.CANONICALIZED_RESOURCES_KEY, List.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED,
                        "Os recursos canonicalizados não foram encontrados no contexto. Verifique se o step json-canonicalizer foi executado."));

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            for (String json : canonicalizedResources) {
                baos.write(json.getBytes(StandardCharsets.UTF_8));
            }

            byte[] hash = MessageDigest.getInstance("SHA-256").digest(baos.toByteArray());
            String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            SigningContext updated = context.toBuilder()
                    .attribute(CONTENT_DIGEST_KEY, base64Url)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED,
                    "Erro ao gerar a impressão digital do conteúdo: " + e.getMessage(), e);
        }
    }
}
