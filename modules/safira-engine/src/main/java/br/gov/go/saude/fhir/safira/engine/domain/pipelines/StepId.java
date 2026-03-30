package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Identifica unicamente um passo para ser referenciado por uma PipelineDefinition.
 *
 * <p>Necessária apenas para steps carregados via Spring/YAML. Consumidores
 * que montam o {@link StepRegistry} programaticamente fornecem os pipelines
 * já resolvidos, sem necessidade desta anotação.</p>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface StepId {
    String value();
}
