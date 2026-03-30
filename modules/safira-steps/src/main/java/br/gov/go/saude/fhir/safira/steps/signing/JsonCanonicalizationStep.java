package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import org.erdtman.jcs.JsonCanonicalizer;

@StepId("json-canonicalizer")
public class JsonCanonicalizationStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        try {
            // Obtém o JSON bruto do Bundle do contexto
            String rawJson = context.getBundle().rawJson();

            // Aplica canonicalização usando a biblioteca oficial RFC 8785
            JsonCanonicalizer canonicalizer = new JsonCanonicalizer(rawJson);
            String canonicalJson = canonicalizer.getEncodedString();

            // Adiciona o JSON canonicalizado ao contexto
            SigningContext updatedContext = context.toBuilder()
                    .attribute("canonicalizedJson", canonicalJson)
                    .build();

            return StepResult.success(getName(), updatedContext);

        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED, "Erro inesperado na canonicalização do JSON: " + e.getMessage(), e);
        }
    }
}
