/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FonteDaSenhaTest {

    private static final String LONGA = "s".repeat(FonteDaSenha.TAMANHO_MAXIMO + 1);

    @TempDir
    Path diretorio;

    private final StringWriter avisos = new StringWriter();

    private String ler(FonteDaSenha fonte) {
        return fonte.ler(new PrintWriter(avisos, true));
    }

    private FonteDaSenha arquivo(String conteudo, String permissoes) throws Exception {
        Path arquivo = Files.writeString(diretorio.resolve("senha.txt"), conteudo);
        Files.setPosixFilePermissions(arquivo, PosixFilePermissions.fromString(permissoes));
        FonteDaSenha fonte = new FonteDaSenha();
        fonte.arquivo = arquivo;
        return fonte;
    }

    @Test
    void shouldReadPasswordFileWithoutTrailingNewline() throws Exception {
        assertThat(ler(arquivo("segredo\n", "rw-------"))).isEqualTo("segredo");
        assertThat(avisos.toString()).isEmpty();
    }

    @Test
    void shouldWarnWhenPasswordFileIsReadableByOthers() throws Exception {
        assertThat(ler(arquivo("segredo\n", "rw-r--r--"))).isEqualTo("segredo");
        assertThat(avisos.toString()).contains("senha.txt").contains("chmod 600");
    }

    @Test
    void shouldRejectPasswordFileAboveLimit() throws Exception {
        FonteDaSenha fonte = arquivo(LONGA, "rw-------");

        assertThatThrownBy(() -> ler(fonte)).isInstanceOf(FalhaDeUso.class).hasMessageContaining("1024")
                .hasMessageContaining("no arquivo de senha").hasMessageNotContaining("em o ");
    }

    @Test
    void shouldRejectPasswordFromStdinAboveLimit() {
        FonteDaSenha fonte = new FonteDaSenha();
        fonte.stdin = true;
        fonte.entrada = new ByteArrayInputStream(LONGA.getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> ler(fonte)).isInstanceOf(FalhaDeUso.class).hasMessageContaining("1024");
    }

    @Test
    void shouldReadFirstLineFromStdin() {
        FonteDaSenha fonte = new FonteDaSenha();
        fonte.stdin = true;
        fonte.entrada = new ByteArrayInputStream("segredo\r\noutra".getBytes(StandardCharsets.UTF_8));

        assertThat(ler(fonte)).isEqualTo("segredo");
    }

    @Test
    void shouldRejectPasswordFromEnvironmentAboveLimit() {
        FonteDaSenha fonte = new FonteDaSenha();
        fonte.variavel = "SENHA";
        fonte.ambiente = Map.of("SENHA", LONGA)::get;

        assertThatThrownBy(() -> ler(fonte)).isInstanceOf(FalhaDeUso.class).hasMessageContaining("1024");
    }

    @Test
    void shouldReadPasswordFromEnvironment() {
        FonteDaSenha fonte = new FonteDaSenha();
        fonte.variavel = "SENHA";
        fonte.ambiente = Map.of("SENHA", "segredo")::get;

        assertThat(ler(fonte)).isEqualTo("segredo");
    }
}
