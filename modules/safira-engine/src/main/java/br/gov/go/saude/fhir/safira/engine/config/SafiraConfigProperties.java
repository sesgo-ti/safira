package br.gov.go.saude.fhir.safira.engine.config;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Propriedades de configuração para as pipelines.
 * <p>
 * Define a versão da Política de Assinatura Digital Avançada, o tipo de operação e os passos
 * necessários para cada operação daquela versão da política.
 */
@ConfigurationProperties(prefix = "safira")
public record SafiraConfigProperties(List<PipelineConfigEntry> pipelines) {

    /**
     * Garante que {@code pipelines} nunca seja {@code null} quando omitido no YAML.
     */
    public SafiraConfigProperties {
        pipelines = (pipelines != null) ? pipelines : List.of();
    }

    /**
     * Entrada de configuração de uma pipeline.
     *
     * @param version   Versão do Guia de Implementação FHIR (Canonical URL | Version).
     *                  Ex: {@code https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0}
     * @param operation Tipo da operação da pipeline ({@code SIGNING} ou {@code VALIDATION}).
     * @param steps     Lista ordenada dos IDs dos passos a serem executados nesta pipeline.
     */
    public record PipelineConfigEntry(
            String version,
            OperationType operation,
            List<String> steps
    ) {}
}
