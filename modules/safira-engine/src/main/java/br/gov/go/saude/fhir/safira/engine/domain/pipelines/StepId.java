package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Identifica unicamente um passo para ser referenciado por uma PipelineDefinition.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface StepId {
    String value();
}
