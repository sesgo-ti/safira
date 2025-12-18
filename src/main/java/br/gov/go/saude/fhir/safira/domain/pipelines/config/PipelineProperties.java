package br.gov.go.saude.fhir.safira.domain.pipelines.config;

import br.gov.go.saude.fhir.safira.domain.OperationType;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Propriedades de configuração para as pipelines
 * <p>
 * Define a versão da Política de Assinatura Digital Avançada, o tipo de operação e os passos
 * necessários para cada operação daquela versão da política.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "safira")
public class PipelineProperties {

    /**
     * Lista de configurações de pipelines.
     */
    private List<PipelineConfigEntry> pipelines = new ArrayList<>();

    @Getter
    @Setter
    public static class PipelineConfigEntry {
        /**
         * Versão do Guia de Implementação FHIR (Canonical URL | Version).
         * Ex: https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0
         */
        private String version;

        /**
         * Tipo da operação da pipeline (SIGNING ou VERIFICATION).
         */
        private OperationType operation;

        /**
         * Lista ordenada dos IDs dos passos a serem executados nesta pipeline.
         */
        private List<String> steps;
    }
}
