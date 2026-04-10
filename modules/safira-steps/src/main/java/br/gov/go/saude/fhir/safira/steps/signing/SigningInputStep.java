package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;

import java.nio.charset.StandardCharsets;

@StepId("signing-input")
public class SigningInputStep implements SigningStep {

    public static final String SIGNING_INPUT_KEY = "signingInput";
    public static final String SIGNING_INPUT_BYTES_KEY = "signingInputBytes";

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        String protectedHeader = context
                .getAttribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O protected header não foi encontrado no contexto. Verifique se o step protected-header foi executado."));

        // Passo 8: o payload é o contentDigest usado diretamente, sem re-codificação Base64Url
        String payload = context
                .getAttribute(ContentDigestStep.CONTENT_DIGEST_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O content digest não foi encontrado no contexto. Verifique se o step content-digest foi executado."));

        // Passo 9: signing input = protectedHeader.payload (RFC 7515 Section 5.1)
        String signingInput = protectedHeader + "." + payload;
        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.UTF_8);

        SigningContext updated = context.toBuilder()
                .attribute(SIGNING_INPUT_KEY, signingInput)
                .attribute(SIGNING_INPUT_BYTES_KEY, signingInputBytes)
                .build();

        return StepResult.success(getName(), updated);
    }
}
