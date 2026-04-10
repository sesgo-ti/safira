package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@StepId("protected-header")
public class ProtectedHeaderStep implements SigningStep {

    public static final String PROTECTED_HEADER_KEY = "protectedHeader";

    private static final int RSA_MIN_BITS = 2048;
    private static final int EC_MIN_BITS = 256;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        X509Certificate signerCert = context.getSignerCertificate()
                .orElseThrow(() -> new IllegalStateException(
                        "Certificado do signatário não disponível no contexto."));

        String alg;
        String keyAlgorithm = signerCert.getPublicKey().getAlgorithm();

        if ("RSA".equals(keyAlgorithm)) {
            RSAPublicKey rsaKey = (RSAPublicKey) signerCert.getPublicKey();
            if (rsaKey.getModulus().bitLength() < RSA_MIN_BITS) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_WEAK_KEY,
                        "Chave RSA com " + rsaKey.getModulus().bitLength()
                                + " bits é inferior ao mínimo de " + RSA_MIN_BITS + " bits.",
                        context);
            }
            alg = "RS256";
        } else if ("EC".equals(keyAlgorithm)) {
            ECPublicKey ecKey = (ECPublicKey) signerCert.getPublicKey();
            int fieldSize = ecKey.getParams().getOrder().bitLength();
            if (fieldSize < EC_MIN_BITS) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_WEAK_KEY,
                        "Chave EC com " + fieldSize
                                + " bits é inferior ao mínimo de " + EC_MIN_BITS + " bits.",
                        context);
            }
            alg = "ES256";
        } else {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                    "Algoritmo de chave pública não suportado: " + keyAlgorithm, context);
        }

        X509Certificate[] chain = context.getCertificateChain()
                .orElse(null);
        if (chain == null || chain.length == 0) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "A cadeia de certificados não está disponível no contexto.", context);
        }

        // Validação temporal do IAT contra o certificado já realizada pelo ChainValidationStep
        Long referenceTimestamp = context.getReferenceTimestamp();
        String policyUri = context.getPolicyIdentifierUri();

        try {
            ObjectNode header = MAPPER.createObjectNode();
            header.put("alg", alg);

            ArrayNode x5cArray = header.putArray("x5c");
            for (X509Certificate cert : chain) {
                x5cArray.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
            }

            if (context.getStrategy() == TimestampStrategy.IAT) {
                header.put("iat", referenceTimestamp);
            }

            ObjectNode sigPId = MAPPER.createObjectNode();
            sigPId.put("id", policyUri);
            header.set("sigPId", sigPId);

            String headerJson = MAPPER.writeValueAsString(header);
            String protectedHeaderB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

            SigningContext updated = context.toBuilder()
                    .attribute(PROTECTED_HEADER_KEY, protectedHeaderB64)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(
                    SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao construir o protected header: " + e.getMessage(), e);
        }
    }
}
