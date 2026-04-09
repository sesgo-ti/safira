package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.IncompleteChainException;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Step: Monta a cadeia de certificados a partir dos dados brutos de entrada.
 *
 * <p>Comportamento:
 * <ul>
 *   <li>1 certificado (leaf only): usa {@link CertificateChainResolver} para completar a cadeia
 *       a partir da âncora de confiança ICP-Brasil.</li>
 *   <li>2+ certificados: decodifica e converte diretamente para {@code X509Certificate[]}.</li>
 * </ul>
 *
 * <p>Em caso de sucesso, o contexto é atualizado com {@code certificateChain} (parsed)
 * para que o step {@code chain-validation} possa validá-la.
 */
@StepId("chain-build")
public class ChainBuildStep implements SigningStep {

    private final CertificateChainResolver chainResolver;

    public ChainBuildStep(CertificateChainResolver chainResolver) {
        this.chainResolver = chainResolver;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        List<String> rawChain = context.getRawCertificateChain();

        if (rawChain == null || rawChain.isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "A cadeia de certificados não foi informada.", context);
        }

        List<X509Certificate> certs = new ArrayList<>();
        for (int i = 0; i < rawChain.size(); i++) {
            byte[] derBytes;
            try {
                derBytes = Base64.getDecoder().decode(rawChain.get(i));
            } catch (IllegalArgumentException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                        "O certificado na posição " + i + " não está codificado em Base64 padrão válido.", context);
            }
            try {
                certs.add(CertificateParser.parse(derBytes));
            } catch (CertificateParsingException | IllegalArgumentException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "O certificado na posição " + i + " não está no formato DER (X.509v3) válido.", context);
            }
        }

        // Monta a cadeia caso o usuário forneça somente 1 certificado (o certificado do signatário)
        X509Certificate[] certArray;
        if (certs.size() == 1) {
            try {
                List<X509Certificate> resolved = chainResolver.resolveChain(certs.getFirst());
                if (resolved == null || resolved.size() < 2) {
                    return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                            "A cadeia resolvida a partir do certificado do signatário não contém certificados suficientes: " +
                                    "é necessário pelo menos o certificado do signatário e a raiz ICP-Brasil.", context);
                }
                certArray = resolved.toArray(new X509Certificate[0]);
            } catch (IncompleteChainException e) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                        "Não foi possível montar a cadeia completa (chegar em um certificado auto-assinado) a partir do certificado do signatário.", context);
            }
        } else {
            certArray = certs.toArray(new X509Certificate[0]);
        }

        return StepResult.success(getName(), context.toBuilder()
                .certificateChain(certArray)
                .build());
    }
}
