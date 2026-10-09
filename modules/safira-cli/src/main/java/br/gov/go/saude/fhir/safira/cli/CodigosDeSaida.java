/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;

import java.util.Optional;
import java.util.Set;

/**
 * Códigos de saída da CLI, alinhados aos do hubsaude CLI (0, 3, 4, 6) mais 1 para erro interno, e o
 * mapeamento do código do IG (CodeSystem {@code situacao-excepcional-assinatura}) para a saída.
 *
 * <p>Na dúvida, o resultado é inconclusivo (4): uma assinatura só é dada como reprovada (6) com
 * evidência clara. Só os códigos que descrevem a assinatura recebida (JWS/JAdES) contam como
 * reprovação na validação; na assinatura, o mesmo código aponta um defeito da entrada (3).
 */
public final class CodigosDeSaida {

    /** Assinatura criada ou validada com sucesso. */
    public static final int SUCESSO = 0;
    /** Falha inesperada (sem stack trace no stdout; causa em stderr com {@code --verbose}). */
    public static final int ERRO_INTERNO = 1;
    /** Erro de uso ou configuração: argumentos, arquivos, JSON, limites, política, allowlist. */
    public static final int USO = 3;
    /** Inconclusivo: INDETERMINATE do DSS, revogação ou carimbo indisponível, acervo indisponível, rede. */
    public static final int INCONCLUSIVO = 4;
    /** Reprovação definitiva: assinatura inválida, certificado revogado, vencido ou não confiável. */
    public static final int REPROVADA = 6;

    /** Operação que produziu o {@code OperationOutcome}. */
    public enum Operacao { ASSINATURA, VALIDACAO }

    private static final Set<String> INCONCLUSIVOS = Set.of(
            "VALIDATION.INDETERMINATE", "VALIDATION.TRY-LATER", "CONFIG.TRUST-STORE-EMPTY",
            "TSA.UNAVAILABLE", "TSA.INVALID-RESPONSE", "SYSTEM.TIMEOUT", "SECURITY.HASH-VALIDATION-FAILED");

    private static final Set<String> DE_USO = Set.of("CRYPTO.KEY-INACCESSIBLE", "CRYPTO.PIN-INVALID");

    /** Códigos {@code FORMAT.*} que, na validação, descrevem a assinatura recebida (reprovação). */
    private static final Set<String> FORMATO_DA_ASSINATURA = Set.of(
            "FORMAT.JWS-MALFORMED", "FORMAT.JWK-INVALID", "FORMAT.CERT-PEM-INVALID");

    private CodigosDeSaida() {
    }

    /** Saída para o {@code OperationOutcome}: a primeira issue {@code error}/{@code fatal} decide; sem ela, sucesso. */
    public static int de(OperationOutcome outcome, Operacao operacao) {
        return outcome.issue().stream()
                .filter(issue -> "error".equals(issue.severity()) || "fatal".equals(issue.severity()))
                .findFirst()
                .map(issue -> codigo(issue).map(codigo -> paraCodigo(codigo, operacao)).orElse(INCONCLUSIVO))
                .orElse(SUCESSO);
    }

    private static Optional<String> codigo(OperationOutcome.Issue issue) {
        if (issue.details() == null || issue.details().coding() == null) {
            return Optional.empty();
        }
        return issue.details().coding().stream().map(Coding::code).filter(codigo -> codigo != null).findFirst();
    }

    static int paraCodigo(String codigo, Operacao operacao) {
        if ("VALIDATION.SUCCESS".equals(codigo)) {
            return SUCESSO;
        }
        if (INCONCLUSIVOS.contains(codigo)) {
            return INCONCLUSIVO;
        }
        if (DE_USO.contains(codigo)) {
            return USO;
        }
        if ("SECURITY.SIGNATURE-VALIDATION-REPLAY".equals(codigo)) {
            return REPROVADA;
        }
        if (codigo.startsWith("FORMAT.")) {
            boolean daAssinatura = FORMATO_DA_ASSINATURA.contains(codigo) || codigo.startsWith("FORMAT.JADES-");
            return operacao == Operacao.VALIDACAO && daAssinatura ? REPROVADA : USO;
        }
        String categoria = codigo.contains(".") ? codigo.substring(0, codigo.indexOf('.')) : codigo;
        return switch (categoria) {
            case "POLICY", "CONFIG", "SECURITY", "MIDDLEWARE", "DEVICE" -> USO;
            case "REVOCATION", "CACHE", "NETWORK" -> INCONCLUSIVO;
            case "CERT", "CRYPTO", "VALIDATION", "TSA", "TEMPORAL" -> REPROVADA;
            case "SYSTEM", "STORAGE" -> ERRO_INTERNO;
            default -> INCONCLUSIVO;
        };
    }
}
