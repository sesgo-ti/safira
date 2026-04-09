package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;

import java.time.Instant;
import java.util.Base64;

@StepId("context-validation")
public class ContextValidationStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        StepResult<SigningContext> fail;

        if ((fail = verifyPolicy(context.getPolicyIdentifierUri(), context)) != null) return fail;
        if ((fail = verifyReferenceTimestamp(context.getReferenceTimestamp(), context)) != null) return fail;
        if ((fail = verifyStrategy(context.getStrategy(), context.getOperationalConfig(), context)) != null) return fail;
        if ((fail = verifyTemporalConstraints(context.getReferenceTimestamp(), context)) != null) return fail;
        if ((fail = verifyOperationalConfigs(context.getOperationalConfig(), context.getCryptoMaterial(), context)) != null) return fail;

        return StepResult.success(getName(), context);
    }

    private StepResult<SigningContext> verifyPolicy(String policyUri, SigningContext context) {
        if (policyUri == null || policyUri.trim().isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_MISSING, "Política de assinatura não fornecida na entrada.", context);
        }

        String expectedPrefix = "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|";
        if (!policyUri.startsWith(expectedPrefix)) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_URI_INVALID, "URI da política não inicia com o prefixo esperado.", context);
        }

        String[] parts = policyUri.split("\\|");
        if (parts.length != 2) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_URI_INVALID, "URI da política deve conter exatamente um separador de versão ('|').", context);
        }

        String version = parts[1];
        if (!version.matches("^\\d+\\.\\d+\\.\\d+$")) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_URI_INVALID, "A versão da política obrigatoriamente segue formato major.minor.patch.", context);
        }
        return null;
    }

    private StepResult<SigningContext> verifyReferenceTimestamp(Long refTs, SigningContext context) {
        if (refTs == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP, "O Timestamp de referência não foi fornecido.", context);
        }
        var security = context.getOperationalConfig().security();
        long min = security.minReferenceTimestamp();
        long max = security.maxReferenceTimestamp();
        if (refTs < min || refTs > max) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TIMEOUT_OUT_OF_RANGE, "O Timestamp de referência está fora do intervalo seguro permitido para assinatura.", context);
        }
        return null;
    }

    private StepResult<SigningContext> verifyStrategy(TimestampStrategy strategy, SafiraOperationalConfigProperties config, SigningContext context) {
        if (strategy == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_INVALID_STRATEGY, "Estratégia do timestamp não declarada na entrada (iat ou tsa).", context);
        }
        if (strategy == TimestampStrategy.TSA) {
            if (config == null || config.verification() == null || 
                config.verification().tsaUrl() == null || config.verification().tsaUrl().isBlank()) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "O uso de Auto-TSA falhou porque a URL da TSA não está configurada.", context);
            }
        }
        return null;
    }

    private StepResult<SigningContext> verifyTemporalConstraints(Long refTs, SigningContext context) {
        long currentTs = Instant.now().getEpochSecond();
        long diff = Math.abs(refTs - currentTs);
        if (diff > 300) {
            return StepResult.failure(getName(), SignatureExceptionCode.TEMPORAL_CLOCK_SKEW_DETECTED, "A diferença entre o timestamp enviado e a hora do servidor é maior que o permitido (>300 segundos).", context);
        }
        return null;
    }

    private StepResult<SigningContext> verifyOperationalConfigs(SafiraOperationalConfigProperties config, CryptoMaterial material, SigningContext context) {
        if (config == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "Faltam configurações operacionais no sistema (SafiraOperationalConfigProperties).", context);
        }

        var vProps = config.verification();
        if (vProps != null) {
            if (vProps.ocspCacheTtl() < 300 || vProps.ocspCacheTtl() > 86400 || vProps.crlCacheTtl() < 300 || vProps.crlCacheTtl() > 86400) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TTL_OUT_OF_RANGE, "A configuração do tempo de cache de revogação (TTL) está fora dos limites permitidos.", context);
            }
            if (vProps.ocspTimeout() < 5 || vProps.ocspTimeout() > 120 || vProps.crlTimeout() < 5 || vProps.crlTimeout() > 120 || vProps.tsaTimeout() < 5 || vProps.tsaTimeout() > 120) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TIMEOUT_OUT_OF_RANGE, "O timeout configurado para requisições online está fora do limite permitido.", context);
            }
            if (vProps.tsaUrl() != null && !vProps.tsaUrl().isBlank() && !vProps.tsaUrl().startsWith("https://")) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TSA_URL_INVALID, "A URL de Auto-TSA deve utilizar o protocolo seguro HTTPS.", context);
            }
        }

        var sProps = config.security();
        if (sProps != null) {
            if (sProps.maxEntriesBundle() < 100 || sProps.maxEntriesBundle() > 10000) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_BUNDLE_SIZE_LIMIT_OUT_OF_RANGE, "O limite de entradas (entries) do Bundle nas configurações está inválido.", context);
            }
            if (sProps.maxBundleSize() < 1048576 || sProps.maxBundleSize() > 209715200) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_BUNDLE_MEMORY_LIMIT_OUT_OF_RANGE, "O limite de tamanho em bytes máximo do Bundle (Payload) configurado é inválido.", context);
            }
            if (sProps.timoutVerificationBundle() < 5 || sProps.timoutVerificationBundle() > 300) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_BUNDLE_TIMEOUT_OUT_OF_RANGE, "O timeout configurado para processamento do Bundle é inválido.", context);
            }
        }

        if (material instanceof CryptoMaterial.Pkcs12Material p12) {
            if (p12.password() == null || p12.password().isEmpty()) {
                return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "A senha do certificado PKCS#12 (p12) não foi fornecida.", context);
            }
            if (p12.alias() != null && p12.alias().length() > 64) {
                return StepResult.failure(getName(), SignatureExceptionCode.MIDDLEWARE_TOKEN_LABEL_INVALID, "O alias do certificado excede o tamanho máximo de 64 caracteres.", context);
            }
            if (p12.contentBase64() != null) {
                try {
                    Base64.getDecoder().decode(p12.contentBase64());
                } catch (IllegalArgumentException ex) {
                    return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID, "O conteúdo do certificado (PKCS#12) enviado não está em formato Base64 válido.", context);
                }
            }
        }
        return null;
    }
}
