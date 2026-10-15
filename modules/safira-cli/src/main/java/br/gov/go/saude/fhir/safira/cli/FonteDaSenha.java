/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine.Option;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Function;

/**
 * Origem da senha do PKCS#12: arquivo, variável de ambiente ou stdin (exatamente uma). A senha nunca é
 * aceita como argumento de linha de comando, onde ficaria visível na lista de processos e no histórico.
 */
final class FonteDaSenha {

    @Option(names = "--senha-arquivo", paramLabel = "ARQUIVO", required = true,
            description = "Arquivo com a senha (uma quebra de linha final é ignorada).")
    Path arquivo;

    @Option(names = "--senha-env", paramLabel = "VARIAVEL", required = true,
            description = "Nome da variável de ambiente com a senha.")
    String variavel;

    @Option(names = "--senha-stdin", required = true, description = "Lê a senha da primeira linha do stdin.")
    boolean stdin;

    /** Teto da senha em bytes (UTF-8), sem a quebra de linha final, em qualquer origem. */
    static final int TAMANHO_MAXIMO = 1024;

    /** Leitura da variável de ambiente (substituível nos testes). */
    Function<String, String> ambiente = System::getenv;

    /** Origem de {@code --senha-stdin}; nula = {@code System.in}. */
    InputStream entrada;

    /** @param avisos stderr: aviso de arquivo de senha legível por grupo ou outros (POSIX) */
    String ler(PrintWriter avisos) {
        if (arquivo != null) {
            return doArquivo(avisos);
        }
        if (variavel != null) {
            String valor = ambiente.apply(variavel);
            if (valor == null) {
                throw new FalhaDeUso("A variável de ambiente " + variavel + " não está definida.");
            }
            return limitada(valor.getBytes(StandardCharsets.UTF_8), "a variável " + variavel);
        }
        return doStdin();
    }

    private String doArquivo(PrintWriter avisos) {
        if (!Files.isRegularFile(arquivo) || !Files.isReadable(arquivo)) {
            throw new FalhaDeUso("Arquivo de senha não encontrado ou ilegível: " + arquivo);
        }
        avisarSeExposto(avisos);
        byte[] conteudo;
        try (InputStream in = Files.newInputStream(arquivo)) {
            conteudo = in.readNBytes(TAMANHO_MAXIMO + 3);
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível ler o arquivo de senha " + arquivo + ".");
        }
        return limitada(semQuebraFinal(conteudo), "o arquivo de senha");
    }

    private void avisarSeExposto(PrintWriter avisos) {
        try {
            Set<PosixFilePermission> permissoes = Files.getPosixFilePermissions(arquivo);
            if (permissoes.stream().anyMatch(EXPOSTAS::contains)) {
                avisos.println("AVISO: o arquivo de senha " + arquivo + " é legível por grupo ou outros; use chmod 600.");
                avisos.flush();
            }
        } catch (UnsupportedOperationException | IOException e) {
            // sem POSIX (ex.: Windows): não há o que conferir
        }
    }

    private String doStdin() {
        InputStream in = entrada != null ? entrada : System.in;
        ByteArrayOutputStream linha = new ByteArrayOutputStream();
        try {
            int lido = in.read();
            if (lido == -1) {
                throw new FalhaDeUso("Nenhuma senha recebida no stdin.");
            }
            for (; lido != -1 && lido != '\n'; lido = in.read()) {
                if (linha.size() > TAMANHO_MAXIMO) {
                    throw excedida("o stdin");
                }
                linha.write(lido);
            }
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível ler a senha do stdin.");
        }
        return limitada(semQuebraFinal(linha.toByteArray()), "o stdin");
    }

    private static String limitada(byte[] senha, String origem) {
        if (senha.length > TAMANHO_MAXIMO) {
            throw excedida(origem);
        }
        return new String(senha, StandardCharsets.UTF_8);
    }

    private static FalhaDeUso excedida(String origem) {
        return new FalhaDeUso("A senha em " + origem + " excede " + TAMANHO_MAXIMO + " bytes.");
    }

    private static byte[] semQuebraFinal(byte[] texto) {
        int fim = texto.length;
        if (fim > 0 && texto[fim - 1] == '\n') {
            fim--;
        }
        if (fim > 0 && texto[fim - 1] == '\r') {
            fim--;
        }
        return Arrays.copyOf(texto, fim);
    }

    private static final Set<PosixFilePermission> EXPOSTAS = EnumSet.of(
            PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE);
}
