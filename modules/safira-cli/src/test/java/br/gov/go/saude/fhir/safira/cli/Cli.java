/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Executa a CLI em processo ({@code CommandLine.execute}) capturando stdout e stderr. */
final class Cli {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Cli() {
    }

    record Resultado(int saida, String out, String err) {

        JsonNode json() {
            try {
                return MAPPER.readTree(out);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        /** Código do IG da primeira issue do {@code OperationOutcome} no stdout. */
        String codigo() {
            return json().get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
        }
    }

    static Resultado executar(String... argumentos) {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
        CommandLine linha = SafiraCli.linhaDeComando();
        linha.setOut(new PrintWriter(out, true));
        linha.setErr(new PrintWriter(err, true));
        int saida = linha.execute(argumentos);
        return new Resultado(saida, out.toString(), err.toString());
    }

    /** Copia o exemplo da política 0.2.0 ({@code bundle.json} ou {@code provenance.json}) para o diretório. */
    static Path exemplo(Path diretorio, String nome) throws Exception {
        return Files.writeString(diretorio.resolve(nome), JadesSigningSystemTest.example(nome));
    }

    static Path escrever(Path arquivo, String conteudo) throws IOException {
        return Files.writeString(arquivo, conteudo);
    }
}
