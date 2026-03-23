package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.OperationalConfig;
import br.gov.go.saude.fhir.safira.engine.domain.ResultStep;
import br.gov.go.saude.fhir.safira.engine.domain.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;

import java.time.Instant;
import java.util.regex.Pattern;

/**
 * Step 1: Verify Inputs (Verificar as entradas).
 * This step enforces the domain validation rules described in sections 1.1 to 1.11 of the signature guide.
 */
public class VerifyInputStep implements Step<SigningContext> {

    // 1.1 URI de Politica
    private static final String POLICY_BASE_URI = "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|";
    private static final Pattern SEMVER_PATTERN = Pattern.compile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$");
    
    // FHIR Timestamp ranges (1º Julho 2025 - 31 Dez 2099)
    private static final long MIN_TIMESTAMP = 1751328000L;
    private static final long MAX_TIMESTAMP = 4102444800L;

    @Override
    public ResultStep<SigningContext> execute(SigningContext context) {
        var err = verifyPolicy(context);
        if (err != null) return err;

        err = verifyReferenceTimestamp(context);
        if (err != null) return err;

        err = verifyStrategy(context);
        if (err != null) return err;

        err = verifyBundleLimits(context);
        if (err != null) return err;

        err = verifyTimestampTolerance(context);
        if (err != null) return err;

        err = verifyOperationalConfig(context);
        if (err != null) return err;

        return new ResultStep.Ok<>(context);
    }

    private ResultStep.Fail<SigningContext> verifyPolicy(SigningContext ctx) {
        String policyId = ctx.getPolicyIdentifierUri();
        if (policyId == null || policyId.isBlank()) return new ResultStep.Fail<>("POLICY.MISSING", "URI da politica ausente");
        if (!policyId.startsWith(POLICY_BASE_URI)) return new ResultStep.Fail<>("POLICY.URI-INVALID", "URI deve iniciar com a base URI");
        String version = policyId.substring(POLICY_BASE_URI.length());
        if (!SEMVER_PATTERN.matcher(version).matches()) return new ResultStep.Fail<>("POLICY.URI-INVALID", "Formato de versao invalido");
        if (!version.equals("0.0.2") && !version.equals("0.1.0")) return new ResultStep.Fail<>("POLICY.VERSION-UNSUPPORTED", "Suportadas: 0.1.0, 0.0.2");
        return null;
    }

    private ResultStep.Fail<SigningContext> verifyReferenceTimestamp(SigningContext ctx) {
        Long ts = ctx.getReferenceTimestamp();
        if (ts == null) return new ResultStep.Fail<>("CONFIG.INVALID-TIMESTAMP-FORMAT", "Timestamp nulo");
        if (ts < MIN_TIMESTAMP || ts > MAX_TIMESTAMP) return new ResultStep.Fail<>("CONFIG.TIMESTAMP-OUT-OF-RANGE", "Requirido [1751328000, 4102444800]");
        return null; 
    }

    private ResultStep.Fail<SigningContext> verifyStrategy(SigningContext ctx) {
        if (ctx.getStrategy() == null) return new ResultStep.Fail<>("CONFIG.INVALID-STRATEGY", "Estrategia nula");
        if (ctx.getStrategy() == TimestampStrategy.TSA) {
            OperationalConfig config = ctx.getOperationalConfig();
            if (config == null || config.verification() == null || config.verification().tsaUrl() == null) {
                return new ResultStep.Fail<>("CONFIG.TSA-CONFIG-MISSING", "URL da TSA nula");
            }
        }
        return null;
    }

    private ResultStep.Fail<SigningContext> verifyBundleLimits(SigningContext ctx) {
        OperationalConfig config = ctx.getOperationalConfig();
        if (config != null && config.security() != null && config.security().maxBundleSize() != null && ctx.getBundleJson() != null) {
            if (ctx.getBundleJson().getBytes().length > config.security().maxBundleSize()) {
                return new ResultStep.Fail<>("SECURITY.BUNDLE-MEMORY-LIMIT-EXCEEDED", "Tamanho do JSON excede maxBundleSize");
            }
        }
        return null;
    }

    private ResultStep.Fail<SigningContext> verifyTimestampTolerance(SigningContext ctx) {
        if (ctx.getReferenceTimestamp() == null) return null; // already caught in verifyReferenceTimestamp
        long diff = Math.abs(ctx.getReferenceTimestamp() - Instant.now().getEpochSecond());
        if (diff > 300) return new ResultStep.Fail<>("TIMESTAMP.OUT-OF-TOLERANCE-WINDOW", "Timestamp difere em mais de 5 minutos do servidor");
        return null;
    }

    private ResultStep.Fail<SigningContext> verifyOperationalConfig(SigningContext ctx) {
        OperationalConfig config = ctx.getOperationalConfig();
        if (config == null) return new ResultStep.Fail<>("CONFIG.MISSING-PARAMETER", "OperationalConfig nulo");
        
        var ver = config.verification();
        if (ver != null) {
            if (ver.ocspCacheTtl() != null && (ver.ocspCacheTtl() < 300 || ver.ocspCacheTtl() > 86400)) return new ResultStep.Fail<>("CONFIG.TTL-OUT-OF-RANGE", "ocspCacheTtl fora do range");
            if (ver.ocspTimeout() != null && (ver.ocspTimeout() < 5 || ver.ocspTimeout() > 120)) return new ResultStep.Fail<>("CONFIG.TIMEOUT-OUT-OF-RANGE", "ocspTimeout fora do range");
            if (ctx.getStrategy() == TimestampStrategy.TSA) {
                if (ver.tsaUrl() == null || !ver.tsaUrl().startsWith("https://")) return new ResultStep.Fail<>("CONFIG.TSA-URL-INVALID", "tsaUrl deve ser https");
            }
        }

        var sec = config.security();
        if (sec != null) {
            if (sec.maxEntriesBundle() != null && (sec.maxEntriesBundle() < 100 || sec.maxEntriesBundle() > 10000)) return new ResultStep.Fail<>("CONFIG.BUNDLE-SIZE-LIMIT-OUT-OF-RANGE", "maxEntries fora do range");
            if (sec.maxBundleSize() != null && (sec.maxBundleSize() < 1048576 || sec.maxBundleSize() > 209715200)) return new ResultStep.Fail<>("CONFIG.BUNDLE-MEMORY-LIMIT-OUT-OF-RANGE", "maxBundleSize fora do range");
            if (sec.timoutVerificationBundle() != null && (sec.timoutVerificationBundle() < 5 || sec.timoutVerificationBundle() > 300)) return new ResultStep.Fail<>("CONFIG.BUNDLE-TIMEOUT-OUT-OF-RANGE", "timoutVerification Bundle fora do range");
        }
        return null;
    }
}
