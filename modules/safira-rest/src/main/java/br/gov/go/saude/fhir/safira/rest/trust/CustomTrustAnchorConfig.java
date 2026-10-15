/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.trust;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Permite confiar numa hierarquia de certificação fora da ICP-Brasil, substituindo inteiramente
 * o acervo oficial pelas raízes indicadas em {@code safira.trust.custom-roots-dir}.
 *
 * <p>Ativado só quando a property está presente ({@link ConditionalOnProperty}): por padrão,
 * nada muda, e o Safira continua usando o {@link TrustMaterialSource} padrão da lib
 * {@code icpbrasil-truststore} (o acervo do ITI), através do mesmo mecanismo de substituição de
 * bean (@{@code ConditionalOnMissingBean}) que a lib já expõe pra esse fim.</p>
 *
 * <p><b>É substituição, não soma</b>: enquanto {@code safira.trust.custom-roots-dir} estiver
 * configurado, nenhuma cadeia ancorada no acervo ICP-Brasil é aceita, só nas raízes desse
 * diretório. Certificado genuíno da ICP-Brasil passa a ser rejeitado por falta de âncora, nesse
 * modo, da mesma forma que um certificado de qualquer outra origem seria.</p>
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SafiraTrustProperties.class)
@ConditionalOnProperty(prefix = "safira.trust", name = "custom-roots-dir")
public class CustomTrustAnchorConfig {

    private static final Logger log = LoggerFactory.getLogger(CustomTrustAnchorConfig.class);
    private static final List<String> EXTENSOES_ACEITAS = List.of(".pem", ".cer", ".crt", ".der");

    @Bean
    @ConditionalOnMissingBean(TrustMaterialSource.class)
    public TrustMaterialSource customTrustMaterialSource(SafiraTrustProperties properties) {
        List<X509Certificate> certificados = carregarCertificados(properties.customRootsDir());
        TrustMaterial material = TrustMaterial.of(certificados);
        if (!material.hasAnchors()) {
            throw new IllegalStateException(
                    "safira.trust.custom-roots-dir (" + properties.customRootsDir() + ") não contém "
                            + "nenhum certificado autoassinado: é preciso ao menos uma raiz de confiança.");
        }
        log.warn("Raiz de confiança personalizada ativa: certificados ICP-Brasil não são aceitos "
                        + "enquanto esse modo estiver ligado ({} certificado(s) carregado(s) de {})",
                certificados.size(), properties.customRootsDir());
        return () -> Optional.of(material);
    }

    private List<X509Certificate> carregarCertificados(String dir) {
        Path diretorio = Path.of(dir);
        if (!Files.isDirectory(diretorio)) {
            throw new IllegalStateException(
                    "safira.trust.custom-roots-dir aponta para um diretório inexistente: " + dir);
        }
        List<X509Certificate> certificados = new ArrayList<>();
        try (DirectoryStream<Path> arquivos = Files.newDirectoryStream(diretorio)) {
            for (Path arquivo : arquivos) {
                String nome = arquivo.getFileName().toString().toLowerCase(Locale.ROOT);
                if (EXTENSOES_ACEITAS.stream().noneMatch(nome::endsWith)) {
                    continue;
                }
                certificados.add(parseCertificado(arquivo, dir));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler certificados de " + dir, e);
        }
        if (certificados.isEmpty()) {
            throw new IllegalStateException(
                    "Nenhum certificado (.pem/.cer/.crt/.der) encontrado em " + dir);
        }
        return certificados;
    }

    private X509Certificate parseCertificado(Path arquivo, String dir) throws IOException {
        try {
            return CertificateParser.parse(Files.readAllBytes(arquivo));
        } catch (CertificateParsingException e) {
            throw new IllegalStateException(
                    "Arquivo " + arquivo.getFileName() + " em " + dir
                            + " não é um certificado X.509 válido.", e);
        }
    }
}
