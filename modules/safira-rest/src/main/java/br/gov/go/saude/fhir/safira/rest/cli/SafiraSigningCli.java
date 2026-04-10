package br.gov.go.saude.fhir.safira.rest.cli;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.rest.Application;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

/**
 * CLI simples para testar o serviço de assinatura Safira com um certificado PKCS#12 real.
 *
 * <p>Uso:
 * <pre>
 * java -cp safira-rest.jar br.gov.go.saude.fhir.safira.rest.cli.SafiraSigningCli \
 *     &lt;pfx-path&gt; &lt;senha&gt; &lt;bundle.json&gt; [provenance.json]
 * </pre>
 *
 * <p>O certificado PKCS#12 é lido do disco, a cadeia e o alias da chave privada são
 * extraídos automaticamente, e a pipeline completa de assinatura é executada via o
 * {@link SigningService} com estratégia IAT. A saída é o recurso FHIR {@link Signature}
 * serializado como JSON.
 *
 * <p>Se o arquivo de Provenance não for fornecido, um Provenance mínimo é gerado
 * referenciando a primeira entry do Bundle.
 */
public class SafiraSigningCli {

    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Uso: safira-cli <pfx-path> <senha> <bundle.json> [provenance.json]");
            System.err.println();
            System.err.println("  pfx-path       — caminho para o arquivo PKCS#12 (.pfx ou .p12)");
            System.err.println("  senha          — senha do PKCS#12");
            System.err.println("  bundle.json    — caminho para o Bundle FHIR");
            System.err.println("  provenance.json — (opcional) caminho para o Provenance FHIR");
            System.exit(2);
        }

        String pfxPath = args[0];
        String password = args[1];
        String bundlePath = args[2];
        String provenancePath = args.length > 3 ? args[3] : null;

        byte[] pfxBytes = Files.readAllBytes(Path.of(pfxPath));
        String alias = findFirstKeyAlias(pfxBytes, password);
        List<String> certChain = extractCertificateChain(pfxBytes, password, alias);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode bundle = mapper.readTree(Files.readString(Path.of(bundlePath)));
        JsonNode provenance = provenancePath != null
                ? mapper.readTree(Files.readString(Path.of(provenancePath)))
                : generateDefaultProvenance(bundle, mapper);

        SigningInput input = new SigningInput(
                bundle,
                provenance,
                new SigningInput.Pkcs12CryptoMaterial(
                        Base64.getEncoder().encodeToString(pfxBytes),
                        password,
                        alias),
                certChain,
                Instant.now().getEpochSecond(),
                "iat",
                POLICY_URI);

        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(Application.class)
                .web(WebApplicationType.NONE)
                .bannerMode(org.springframework.boot.Banner.Mode.OFF)
                .logStartupInfo(false)
                .run()) {

            SigningService signingService = ctx.getBean(SigningService.class);
            PipelineResult<?> result = signingService.sign(input);

            if (result.isSuccess()) {
                Signature signature = (Signature) result.getValue();
                String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signature);
                System.out.println(json);
                System.exit(0);
            } else {
                System.err.println("Falha na assinatura:");
                System.err.println(mapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(result.getExceptionDetails()));
                System.exit(1);
            }
        }
    }

    private static String findFirstKeyAlias(byte[] pfxBytes, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfxBytes), password.toCharArray());
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException("Nenhuma chave privada encontrada no arquivo PKCS#12.");
    }

    private static List<String> extractCertificateChain(byte[] pfxBytes, String password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfxBytes), password.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("O alias '" + alias + "' não possui cadeia de certificados.");
        }
        List<String> result = new ArrayList<>();
        for (Certificate cert : chain) {
            result.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
        }
        return result;
    }

    private static JsonNode generateDefaultProvenance(JsonNode bundle, ObjectMapper mapper) {
        ObjectNode provenance = mapper.createObjectNode();
        provenance.put("resourceType", "Provenance");
        provenance.put("id", UUID.randomUUID().toString());

        ArrayNode target = provenance.putArray("target");
        JsonNode entries = bundle.get("entry");
        if (entries != null && entries.isArray()) {
            for (JsonNode entry : entries) {
                JsonNode fullUrl = entry.get("fullUrl");
                if (fullUrl != null && fullUrl.isTextual()) {
                    target.addObject().put("reference", fullUrl.asText());
                }
            }
        }
        if (target.isEmpty()) {
            throw new IllegalStateException(
                    "Não foi possível gerar Provenance: o Bundle não contém entries com fullUrl.");
        }
        return provenance;
    }
}
