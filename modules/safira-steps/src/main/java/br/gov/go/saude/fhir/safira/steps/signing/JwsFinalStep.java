package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.revocation.RevocationEvidence;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Step: monta a estrutura JWS final (passo 13 da especificação).
 *
 * <p>Adiciona o unprotected header à estrutura JWS preliminar produzida pelo
 * {@link JwsPreliminaryStep}. O unprotected header contém:
 * <ul>
 *   <li>{@code rRefs.ocspRefs[]} — hashes SHA-512 (em Base64) das respostas OCSP coletadas</li>
 *   <li>{@code rRefs.crlRefs[]} — hashes SHA-512 (em Base64) das CRLs coletadas</li>
 *   <li>{@code sigTst} — token TSA em Base64 (apenas para estratégia TSA)</li>
 * </ul>
 *
 * <p>A estrutura completa é serializada como String JSON compacta (sem formatação) e
 * armazenada em {@code "jwsFinal"}.
 */
@StepId("jws-final")
public class JwsFinalStep implements SigningStep {

    public static final String JWS_FINAL_KEY = "jwsFinal";

    private static final String SHA512_DIGEST_ALG = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @SuppressWarnings("unchecked")
    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        // deepCopy para não mutar o ObjectNode compartilhado no contexto — mantém o step puro.
        ObjectNode jws = context
                .getAttribute(JwsPreliminaryStep.JWS_PRELIMINARY_KEY, ObjectNode.class)
                .map(ObjectNode::deepCopy)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A estrutura JWS preliminar não foi encontrada no contexto."));

        List<RevocationEvidence> evidences = context
                .getAttribute(ChainValidationStep.REVOCATION_EVIDENCES_KEY, List.class)
                .orElse(List.of());

        ObjectNode unprotectedHeader = MAPPER.createObjectNode();

        if (context.getStrategy() == TimestampStrategy.TSA) {
            String tsaToken = context
                    .getAttribute(TsaTimestampStep.TSA_TOKEN_KEY, String.class)
                    .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                            "O token TSA não foi encontrado no contexto (estratégia TSA exige o token)."));
            unprotectedHeader.put("sigTst", tsaToken);
        }

        ObjectNode rRefs = buildRevocationRefs(evidences);
        if (rRefs != null) {
            unprotectedHeader.set("rRefs", rRefs);
        }

        if (!unprotectedHeader.isEmpty()) {
            ObjectNode signatureEntry = (ObjectNode) jws.get("signatures").get(0);
            signatureEntry.set("header", unprotectedHeader);
        }

        try {
            String jwsFinal = MAPPER.writeValueAsString(jws);
            SigningContext updated = context.toBuilder()
                    .attribute(JWS_FINAL_KEY, jwsFinal)
                    .build();
            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao serializar a estrutura JWS final: " + e.getMessage(), e);
        }
    }

    private ObjectNode buildRevocationRefs(List<RevocationEvidence> evidences) {
        if (evidences == null || evidences.isEmpty()) {
            return null;
        }

        ArrayNode ocspRefs = MAPPER.createArrayNode();
        ArrayNode crlRefs = MAPPER.createArrayNode();

        for (RevocationEvidence evidence : evidences) {
            ObjectNode ref = buildDigestRef(evidence.hashSha512());
            if ("OCSP".equals(evidence.source())) {
                ocspRefs.add(ref);
            } else if ("CRL".equals(evidence.source())) {
                crlRefs.add(ref);
            }
        }

        if (ocspRefs.isEmpty() && crlRefs.isEmpty()) {
            return null;
        }

        ObjectNode rRefs = MAPPER.createObjectNode();
        if (!ocspRefs.isEmpty()) {
            rRefs.set("ocspRefs", ocspRefs);
        }
        if (!crlRefs.isEmpty()) {
            rRefs.set("crlRefs", crlRefs);
        }
        return rRefs;
    }

    private ObjectNode buildDigestRef(String hexHash) {
        ObjectNode ref = MAPPER.createObjectNode();
        ref.put("digestAlg", SHA512_DIGEST_ALG);
        byte[] hashBytes = HexFormat.of().parseHex(hexHash);
        ref.put("digestValue", Base64.getEncoder().encodeToString(hashBytes));
        return ref;
    }
}
