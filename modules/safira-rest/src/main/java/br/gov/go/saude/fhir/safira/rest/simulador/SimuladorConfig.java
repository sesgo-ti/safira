/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.simulador;

import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Optional;

/**
 * Ativo só com {@code --spring.profiles.active=simulado} (nunca em produção).
 *
 * <p>Substitui dois beans da auto-configuração da lib {@code icpbrasil-truststore}:
 * {@link TrustMaterialSource} (âncora de confiança) e {@link RevocationService}
 * (OCSP/CRL), por uma PKI fictícia gerada do zero a cada subida ({@link SimuladorPki}).
 * Ambos os beans da lib são registrados com {@code @ConditionalOnMissingBean}, então estes
 * aqui os substituem automaticamente, sem exigir nenhuma mudança na auto-configuração
 * original.</p>
 *
 * <p>{@code PkixCertificateValidator} continua sendo o bean real da lib: ele só passa a
 * receber estas substituições como dependências, então a construção/validação de cadeia
 * (RFC 5280, via {@code CertPathBuilder}/{@code CertPathValidator} do JDK) continua
 * acontecendo de verdade, só ancorada numa raiz fictícia em vez do acervo real do ITI. A
 * verificação de <strong>revogação</strong>, por outro lado, é inteiramente simulada: o
 * {@link SimuladorRevocationService} sempre responde {@code GOOD}, sem checagem real.</p>
 *
 * <p>Nada aqui é fixo: a CA e o certificado-folha são gerados em memória a cada subida,
 * não há chave nem certificado commitados no repositório nem reaproveitados entre
 * execuções. O {@code signer.pem}/{@code signer-key.pem} gravados em disco continuam
 * fisicamente ali depois que a aplicação para, mas só são aceitos pela allowlist da
 * instância que os gerou: a próxima subida gera uma CA diferente e os anteriores deixam
 * de corresponder a ela.</p>
 *
 * <p>A allowlist de política (que normalmente vem do {@code application.yml}) também é
 * montada aqui em Java, porque o SHA-256 da CA muda a cada subida: isso significa que
 * {@code safira.policy.*} configurado no {@code application.yml} é <strong>ignorado</strong>
 * enquanto este profile está ativo.</p>
 */
@Configuration(proxyBeanMethods = false)
@Profile("simulado")
class SimuladorConfig {

    private static final Logger log = LoggerFactory.getLogger(SimuladorConfig.class);

    @Bean
    SimuladorPki simuladorPki() {
        return new SimuladorPki();
    }

    @Bean
    TrustMaterialSource trustMaterialSource(SimuladorPki pki) {
        TrustMaterial material = TrustMaterial.anchoredAt(List.of(pki.caCert()));
        return () -> Optional.of(material);
    }

    @Bean
    RevocationService revocationService(SimuladorPki pki) {
        return new SimuladorRevocationService(pki);
    }

    /**
     * Substitui a {@link SafiraPolicyProperties} vinda do {@code application.yml} (que teria
     * um {@code issuer-sha256} fixo, impossível de acertar com uma CA gerada na hora).
     * {@code @Primary} garante que esta instância vence a vinculada por
     * {@code @ConfigurationProperties} quando os dois beans existem no contexto.
     */
    @Bean
    @Primary
    SafiraPolicyProperties simuladorPolicyProperties(SimuladorPki pki) {
        var allowlist = new SafiraPolicyProperties.AcceptedCertificatePolicy(
                pki.oid(), CertificateType.A3, pki.issuerSha256());
        return new SafiraPolicyProperties(List.of(allowlist), null, null);
    }

    /** Grava o certificado-folha e a chave gerados nesta subida, e avisa onde estão. */
    @Bean
    CommandLineRunner simuladorAvisoInicial(SimuladorPki pki) {
        return args -> {
            // Inclui o usuário no caminho: evita colisão de permissão quando outro usuário da
            // mesma máquina já criou o diretório, e funciona também no Windows.
            Path dir = Path.of(System.getProperty("java.io.tmpdir"),
                    "safira-simulado-" + System.getProperty("user.name"));
            Files.createDirectories(dir);
            Path certPath = dir.resolve("signer.pem");
            Path keyPath = dir.resolve("signer-key.pem");
            Files.writeString(certPath, pki.leafCertPem());
            Files.writeString(keyPath, pki.leafKeyPem());
            tentarRestringirPermissao(keyPath);

            log.warn("Simulador ativo, nunca usar em produção.");
            log.warn("Certificado-folha e chave gerados nesta subida (válidos só enquanto esta instância estiver no ar):");
            log.warn("  {}", certPath);
            log.warn("  {}", keyPath);
            log.warn("Veja docs/simulacao-sem-certificado-real.md para montar a requisição de /assinar.");
        };
    }

    /** Restringe a chave a leitura/escrita só do dono, quando o sistema de arquivos suporta POSIX. */
    private static void tentarRestringirPermissao(Path keyPath) {
        try {
            Files.setPosixFilePermissions(keyPath, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            log.debug("Sistema de arquivos sem suporte a permissões POSIX; chave gravada com permissão padrão do SO.");
        }
    }
}
