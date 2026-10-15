/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.simulador.RepositorioPkiSimulada;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import tools.jackson.databind.json.JsonMapper;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/** {@code safira simulador}: utilidades da PKI simulada (SEM VALOR LEGAL). */
@Command(name = "simulador", description = "Utilidades da PKI simulada (SEM validade jurídica ICP-Brasil).",
        subcommands = Simulador.Pki.class)
final class Simulador implements Runnable {

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        throw new ParameterException(spec.commandLine(), "informe um comando: pki.");
    }

    /**
     * {@code safira simulador pki}: gera a PKI na primeira vez (ou reutiliza a existente) e imprime os
     * caminhos dos arquivos e os valores da allowlist. A senha dos PKCS#12 nunca sai: só o caminho do arquivo.
     */
    @Command(name = "pki", description = "Mostra (e gera na primeira vez) a PKI simulada persistida: caminhos e allowlist.")
    static final class Pki implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Option(names = "--pki-dir", paramLabel = "DIR",
                description = "Diretório da PKI simulada (padrão SAFIRA_SIMULADOR_DIRETORIO ou ~/.safira-simulador/pki).")
        Path pkiDir;

        @Override
        public Integer call() {
            PrintWriter err = spec.commandLine().getErr();
            err.println("AVISO: " + AvisoSimulacaoAdvice.TEXTO);
            PkiPersistida pki;
            try {
                pki = RepositorioPkiSimulada.abrir(OpcoesComuns.diretorioDaPki(pkiDir));
            } catch (RuntimeException e) {
                err.println("Erro: não foi possível abrir a PKI simulada: " + e.getMessage());
                return CodigosDeSaida.USO;
            }
            Map<String, Object> json = new LinkedHashMap<>();
            json.put("diretorio", pki.diretorio().toString());
            json.put("situacao", pki.situacao().name());
            json.put("raiz", pki.raiz().toString());
            json.put("ac", pki.ac().toString());
            json.put("signatario", pki.signatario().toString());
            json.put("alias", GeradorPkiSimulada.ALIAS_SIGNATARIO);
            json.put("revogado", pki.revogado().toString());
            json.put("aliasRevogado", GeradorPkiSimulada.ALIAS_REVOGADO);
            json.put("senha", pki.senha().toString());
            json.put("politicaOid", pki.politicaOid());
            json.put("issuerSha256", pki.issuerSha256());
            json.put("validadeSignatario", pki.pki().signatario().getNotAfter().toInstant().toString());
            json.put("simulacao", AvisoSimulacaoAdvice.TEXTO);
            PrintWriter out = spec.commandLine().getOut();
            out.println(JsonMapper.builder().build().writeValueAsString(json));
            out.flush();
            return out.checkError() ? CodigosDeSaida.ERRO_INTERNO : CodigosDeSaida.SUCESSO;
        }
    }
}
