package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

/**
 * Step: verificação criptográfica da assinatura JWS (spec §4).
 *
 * <p>Reconstrói o signing input ({@code protectedHeader + "." + payload}), extrai a chave
 * pública do certificado folha e verifica com {@code SHA256withRSA} (RS256) ou
 * {@code SHA256withECDSA} (ES256).
 */
@StepId("validation-signature-verification")
public class SignatureCryptoVerificationStep implements ValidationStep {

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) throws StepException {
        Map<String, Object> protectedHeader = context.getProtectedHeader();
        String alg = protectedHeader == null ? null : (String) protectedHeader.get("alg");
        if (alg == null || (!"RS256".equals(alg) && !"ES256".equals(alg))) {
            throw new StepException(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Algoritmo não suportado pelo step de verificação criptográfica: " + alg);
        }

        List<X509Certificate> chain = context.getCertificateChain().orElse(List.of());
        if (chain.isEmpty()) {
            throw new StepException(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Cadeia de certificados vazia ao verificar a assinatura.");
        }
        X509Certificate leaf = chain.get(0);
        PublicKey publicKey = leaf.getPublicKey();

        byte[] signatureBytes = context.getSignatureBytes();
        if (signatureBytes == null) {
            throw new StepException(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Bytes da assinatura ausentes no contexto.");
        }

        // Validar compatibilidade alg/chave
        if ("RS256".equals(alg) && !(publicKey instanceof RSAPublicKey)) {
            return StepResult.failure(getName(),
                    SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Algoritmo RS256 é incompatível com chave pública do tipo " +
                            publicKey.getAlgorithm() + ".", context);
        }
        if ("ES256".equals(alg) && !(publicKey instanceof ECPublicKey)) {
            return StepResult.failure(getName(),
                    SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Algoritmo ES256 é incompatível com chave pública do tipo " +
                            publicKey.getAlgorithm() + ".", context);
        }

        byte[] jcaSigBytes = signatureBytes;
        if ("ES256".equals(alg)) {
            if (signatureBytes.length != 64) {
                return StepResult.failure(getName(),
                        SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                        "Assinatura ES256 deve conter exatamente 64 bytes (r||s); recebido: " +
                                signatureBytes.length + ".", context);
            }
            jcaSigBytes = rsToDer(signatureBytes);
        }

        String signingInput = (context.getRawProtectedHeaderBase64Url() == null ? ""
                : context.getRawProtectedHeaderBase64Url())
                + "." + (context.getPayloadBase64Url() == null ? "" : context.getPayloadBase64Url());

        String jcaAlg = "RS256".equals(alg) ? "SHA256withRSA" : "SHA256withECDSA";
        try {
            Signature verifier = Signature.getInstance(jcaAlg);
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(jcaSigBytes)) {
                return StepResult.failure(getName(),
                        SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                        "Verificação criptográfica da assinatura falhou.", context);
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new StepException(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "Erro técnico ao verificar assinatura: " + e.getMessage(), e);
        }

        return StepResult.success(getName(), context);
    }

    /**
     * Converts a P-256 ECDSA signature in raw r||s form (64 bytes) to DER ASN.1:
     * {@code SEQUENCE { INTEGER r, INTEGER s }}. Leading zero bytes are prepended
     * if the high bit of r or s is set (to preserve positive integer semantics).
     */
    private static byte[] rsToDer(byte[] raw) {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(raw, 0, r, 0, 32);
        System.arraycopy(raw, 32, s, 0, 32);

        byte[] rEnc = toDerInteger(r);
        byte[] sEnc = toDerInteger(s);
        int seqLen = rEnc.length + sEnc.length;

        byte[] out;
        if (seqLen < 128) {
            out = new byte[2 + seqLen];
            out[0] = 0x30;
            out[1] = (byte) seqLen;
            System.arraycopy(rEnc, 0, out, 2, rEnc.length);
            System.arraycopy(sEnc, 0, out, 2 + rEnc.length, sEnc.length);
        } else {
            out = new byte[3 + seqLen];
            out[0] = 0x30;
            out[1] = (byte) 0x81;
            out[2] = (byte) seqLen;
            System.arraycopy(rEnc, 0, out, 3, rEnc.length);
            System.arraycopy(sEnc, 0, out, 3 + rEnc.length, sEnc.length);
        }
        return out;
    }

    private static byte[] toDerInteger(byte[] value) {
        int start = 0;
        while (start < value.length - 1 && value[start] == 0) {
            start++;
        }
        boolean needsLeadingZero = (value[start] & 0x80) != 0;
        int len = value.length - start + (needsLeadingZero ? 1 : 0);
        byte[] out = new byte[2 + len];
        out[0] = 0x02;
        out[1] = (byte) len;
        int dst = 2;
        if (needsLeadingZero) {
            out[dst++] = 0x00;
        }
        System.arraycopy(value, start, out, dst, value.length - start);
        return out;
    }
}
