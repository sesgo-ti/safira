/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.HttpTsaClient;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.TsaClient;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.TsaInvalidResponseException;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.TsaUnavailableException;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Step: obtém carimbo de tempo TSA (passo 12 da especificação).
 *
 * <p>Quando a estratégia de timestamp é {@link TimestampStrategy#TSA}, gera uma requisição
 * RFC 3161 com hash SHA-256 da assinatura criptográfica, delega o envio a um {@link TsaClient}
 * injetável, valida a resposta e armazena o token TSA codificado em Base64 no contexto.
 *
 * <p>Para estratégia {@link TimestampStrategy#IAT}, o step é no-op.
 *
 * <p><b>Validações do token retornado:</b>
 * <ul>
 *   <li>Resposta da TSA deve ser bem-sucedida (status PKIStatus.GRANTED ou GRANTED_WITH_MODS)</li>
 *   <li>Hash submetido deve corresponder ao hash calculado localmente</li>
 *   <li>Timestamp do token deve estar a ±5 minutos de {@code referenceTimestamp}</li>
 *   <li>Timestamp deve estar dentro da validade do certificado do signatário</li>
 * </ul>
 */
@StepId("tsa-timestamp")
public class TsaTimestampStep implements SigningStep {

    public static final String TSA_TOKEN_KEY = "tsaToken";

    private static final int TOLERANCE_SECONDS = 300;
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;

    private final TsaClient tsaClient;
    private final SecureRandom random = new SecureRandom();

    public TsaTimestampStep() {
        this(new HttpTsaClient());
    }

    public TsaTimestampStep(TsaClient tsaClient) {
        this.tsaClient = tsaClient;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        if (context.getStrategy() != TimestampStrategy.TSA) {
            return StepResult.success(getName(), context);
        }

        String signatureB64Url = context
                .getAttribute(CryptoSigningStep.SIGNATURE_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A assinatura criptográfica não foi encontrada no contexto."));

        String tsaUrl = resolveTsaUrl(context);
        if (tsaUrl == null || tsaUrl.isBlank()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TSA_CONFIG_MISSING,
                    "URL da TSA não foi configurada.", context);
        }

        int timeoutSeconds = resolveTimeoutSeconds(context);

        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureB64Url);
            byte[] signatureHash = MessageDigest.getInstance("SHA-256").digest(signatureBytes);

            TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
            generator.setCertReq(true);
            TimeStampRequest request = generator.generate(
                    TSPAlgorithms.SHA256, signatureHash, new BigInteger(64, random));

            TimeStampResponse response = tsaClient.requestTimestamp(tsaUrl, request, timeoutSeconds);

            response.validate(request);

            TimeStampToken token = response.getTimeStampToken();
            if (token == null) {
                return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_RESPONSE,
                        "A TSA não retornou um token válido: " + response.getStatusString(), context);
            }

            TSTInfo tstInfo = token.getTimeStampInfo().toASN1Structure();
            long tokenEpoch = tstInfo.getGenTime().getDate().toInstant().getEpochSecond();

            long refTs = context.getReferenceTimestamp();
            if (Math.abs(tokenEpoch - refTs) > TOLERANCE_SECONDS) {
                return StepResult.failure(getName(),
                        SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS,
                        "O timestamp da TSA (" + tokenEpoch + ") está fora da janela de tolerância "
                                + "de ±" + TOLERANCE_SECONDS + " segundos do timestamp de referência (" + refTs + ").",
                        context);
            }

            Optional<X509Certificate> signerCert = context.getSignerCertificate();
            if (signerCert.isPresent()) {
                Instant tokenInstant = Instant.ofEpochSecond(tokenEpoch);
                X509Certificate cert = signerCert.get();
                if (tokenInstant.isBefore(cert.getNotBefore().toInstant())
                        || tokenInstant.isAfter(cert.getNotAfter().toInstant())) {
                    return StepResult.failure(getName(),
                            SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS,
                            "O timestamp da TSA está fora do período de validade do certificado do signatário.",
                            context);
                }
            }

            String tokenB64 = Base64.getEncoder().encodeToString(token.getEncoded());

            return StepResult.success(getName(), context.toBuilder()
                    .attribute(TSA_TOKEN_KEY, tokenB64)
                    .build());

        } catch (TsaUnavailableException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_UNAVAILABLE,
                    "Não foi possível obter resposta da TSA: " + e.getMessage(), context);
        } catch (TsaInvalidResponseException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_RESPONSE,
                    "A resposta da TSA é inválida: " + e.getMessage(), context);
        } catch (org.bouncycastle.tsp.TSPException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_VALIDATION_FAILED,
                    "Falha na validação criptográfica do token TSA: " + e.getMessage(), context);
        } catch (StepException e) {
            throw e;
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.TSA_VALIDATION_FAILED,
                    "Erro inesperado na obtenção do carimbo de tempo: " + e.getMessage(), e);
        }
    }

    private String resolveTsaUrl(SigningContext context) {
        if (context.getOperationalConfig() == null
                || context.getOperationalConfig().verification() == null) {
            return null;
        }
        return context.getOperationalConfig().verification().tsaUrl();
    }

    private int resolveTimeoutSeconds(SigningContext context) {
        if (context.getOperationalConfig() != null
                && context.getOperationalConfig().verification() != null
                && context.getOperationalConfig().verification().tsaTimeout() != null) {
            return context.getOperationalConfig().verification().tsaTimeout();
        }
        return DEFAULT_TIMEOUT_SECONDS;
    }
}
