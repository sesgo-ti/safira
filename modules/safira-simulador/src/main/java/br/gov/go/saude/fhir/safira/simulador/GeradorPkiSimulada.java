/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import br.gov.go.saude.fhir.safira.testkit.PerfilSignatario;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Grava em arquivos uma PKI de simulação (SEM VALOR LEGAL) gerada pelo {@link PkiIcpSimulada} do
 * testkit (PKI factory do EU DSS): raiz, AC intermediária, signatário A3-like e um segundo signatário
 * revogado, LCRs da raiz e da AC e um trecho {@code application-simulacao.yml} com caminhos e
 * allowlist prontos. O {@link Resultado} guarda a PKI, cujas fontes OCSP, LCR e TSA em memória
 * servem à aplicação do simulador.
 *
 * <p>Uso avulso: {@code java -cp safira-simulador-<versão>-exec.jar
 * -Dloader.main=br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada
 * org.springframework.boot.loader.launch.PropertiesLauncher --saida <dir> [--senha <senha>]
 * [--politica <oid A3>] [--cpf <11 dígitos>]}. Sem {@code --senha}, gera uma senha aleatória e a
 * imprime; a senha informada nunca é impressa. Os PKCS#12 são gravados com permissão 0600 (POSIX).
 */
public final class GeradorPkiSimulada {

    public static final String ALIAS_SIGNATARIO = "signatario";
    public static final String ALIAS_REVOGADO = "revogado";
    /** Política A3 do testkit, a mesma do signatário revogado (o revogado não segue {@code --politica}). */
    public static final String POLITICA_PADRAO = "2.16.76.1.2.3.1";
    public static final String CPF_PADRAO = "52998224725";
    public static final String MARCA = PkiIcpSimulada.MARCA;

    private static final SecureRandom RANDOM = new SecureRandom();

    private GeradorPkiSimulada() {
    }

    /**
     * Parâmetros da geração.
     *
     * @param senha       senha dos PKCS#12
     * @param politicaOid OID de política A3 ({@code 2.16.76.1.2.3.n}) no certificado folha
     * @param cpf         CPF do titular (dígitos verificadores válidos)
     */
    public record Opcoes(String senha, String politicaOid, String cpf) {

        public Opcoes {
            if (senha == null || senha.isEmpty()) {
                throw new IllegalArgumentException("A senha do PKCS#12 não pode ser vazia.");
            }
            if (!CertificateType.A3.matchesBranch(politicaOid)) {
                throw new IllegalArgumentException("Política deve ser A3 (2.16.76.1.2.3.<n>): " + politicaOid);
            }
            if (!IcpBrasilCertificateProfile.isValidCpf(cpf)) {
                throw new IllegalArgumentException("CPF inválido (11 dígitos com verificadores): " + cpf);
            }
        }

        public static Opcoes padrao() {
            return new Opcoes(senhaAleatoria(), POLITICA_PADRAO, CPF_PADRAO);
        }

        public Opcoes comSenha(String valor) {
            return new Opcoes(valor, politicaOid, cpf);
        }

        public Opcoes comPoliticaOid(String valor) {
            return new Opcoes(senha, valor, cpf);
        }

        public Opcoes comCpf(String valor) {
            return new Opcoes(senha, politicaOid, valor);
        }
    }

    /**
     * Arquivos gerados, valores para a allowlist {@code safira.policy.accepted-certificate-policies}
     * e a PKI em memória (fontes OCSP, LCR e TSA).
     */
    public record Resultado(Path raiz, Path ac, Path signatario, Path revogado, Path lcrRaiz, Path lcrAc, Path yaml,
                            String senha, String politicaOid, String issuerSha256, PkiIcpSimulada pki) {
    }

    public static void main(String[] args) {
        Map<String, String> argumentos = argumentos(args);
        String saida = argumentos.remove("--saida");
        if (saida == null) {
            System.err.println("Uso: GeradorPkiSimulada --saida <dir> [--senha <senha>] [--politica <oid A3>] [--cpf <cpf>]");
            System.exit(2);
        }
        Opcoes opcoes = Opcoes.padrao();
        boolean senhaInformada = argumentos.containsKey("--senha");
        if (senhaInformada) {
            opcoes = opcoes.comSenha(argumentos.remove("--senha"));
        }
        if (argumentos.containsKey("--politica")) {
            opcoes = opcoes.comPoliticaOid(argumentos.remove("--politica"));
        }
        if (argumentos.containsKey("--cpf")) {
            opcoes = opcoes.comCpf(argumentos.remove("--cpf"));
        }
        if (!argumentos.isEmpty()) {
            throw new IllegalArgumentException("Argumentos desconhecidos: " + argumentos.keySet());
        }
        Resultado resultado = gerar(Path.of(saida), opcoes);
        System.out.println("PKI de simulação (" + MARCA + ") gerada em " + resultado.raiz().getParent());
        // Senha informada pelo operador nunca é ecoada (vazaria em logs de CI); só a gerada é exibida.
        System.out.println("  senha dos PKCS#12 : " + (senhaInformada ? "(a informada em --senha)" : resultado.senha()));
        System.out.println("  aliases           : " + ALIAS_SIGNATARIO + ", " + ALIAS_REVOGADO);
        System.out.println("  política (OID)    : " + resultado.politicaOid());
        System.out.println("  issuer-sha256 (AC): " + resultado.issuerSha256());
        System.out.println("  configuração      : " + resultado.yaml());
    }

    private static Map<String, String> argumentos(String[] args) {
        Map<String, String> mapa = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--") || i + 1 >= args.length) {
                throw new IllegalArgumentException("Argumento sem valor: " + args[i]);
            }
            mapa.put(args[i], args[++i]);
        }
        return mapa;
    }

    /** Gera todos os artefatos em {@code saida} (criada se não existir), sobrescrevendo os anteriores. */
    public static Resultado gerar(Path saida, Opcoes opcoes) {
        try {
            Files.createDirectories(saida);
            Path dir = saida.toAbsolutePath().normalize();
            PkiIcpSimulada pki = PkiIcpSimulada.criar(perfil(opcoes));

            Resultado resultado = new Resultado(dir.resolve("raiz.pem"), dir.resolve("ac.pem"),
                    dir.resolve("signatario.p12"), dir.resolve("revogado.p12"), dir.resolve("lcr-raiz.crl"),
                    dir.resolve("lcr-ac.crl"), dir.resolve("application-simulacao.yml"), opcoes.senha(),
                    opcoes.politicaOid(), IcpBrasilCertificateProfile.sha256Hex(pki.ac()), pki);

            Files.writeString(resultado.raiz(), pem(pki.raiz()));
            Files.writeString(resultado.ac(), pem(pki.ac()));
            p12(resultado.signatario(), ALIAS_SIGNATARIO, pki.chavesSignatario(), opcoes.senha(),
                    pki.signatario(), pki.ac(), pki.raiz());
            p12(resultado.revogado(), ALIAS_REVOGADO, pki.chavesRevogado(), opcoes.senha(),
                    pki.revogado(), pki.ac(), pki.raiz());
            Files.write(resultado.lcrRaiz(), pki.lcrDaRaiz());
            Files.write(resultado.lcrAc(), pki.lcr());
            Files.writeString(resultado.yaml(), yaml(resultado));
            return resultado;
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar a PKI de simulação em " + saida, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao gerar a PKI de simulação", e);
        }
    }

    /** Signatário A3 com a política e o CPF das opções (DN com SERIALNUMBER e otherName CPF no SAN). */
    private static PerfilSignatario perfil(Opcoes opcoes) {
        return PerfilSignatario.a3()
                .comPolitica(opcoes.politicaOid())
                .comDn("CN=FULANO SIMULADO:" + opcoes.cpf() + ",SERIALNUMBER=" + opcoes.cpf() + ",O=" + MARCA + ",C=BR")
                .comSan(PerfilSignatario.SAN_CPF, "01011990" + opcoes.cpf() + "0".repeat(18));
    }

    private static String yaml(Resultado r) {
        return """
                # PKI de simulação (%s) gerada pelo GeradorPkiSimulada.
                # Uso: numa aplicação com safira-rest e safira-simulador,
                #        --spring.profiles.active=simulacao --spring.config.additional-location=file:%s/
                safira:
                  simulacao:
                    enabled: true
                    trust-anchors: "%s"
                    intermediates: "%s"
                    crls:
                      - "%s"
                      - "%s"
                  policy:
                    accepted-certificate-policies:
                      - oid: "%s"
                        type: A3
                        issuer-sha256: "%s"
                """.formatted(MARCA, r.raiz().getParent(), r.raiz().toUri(), r.ac().toUri(), r.lcrRaiz().toUri(),
                r.lcrAc().toUri(), r.politicaOid(), r.issuerSha256());
    }

    private static void p12(Path destino, String alias, KeyPair chaves, String senha,
                            X509Certificate... cadeia) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, chaves.getPrivate(), senha.toCharArray(), (Certificate[]) cadeia);
        try (OutputStream out = arquivoPrivado(destino)) {
            keyStore.store(out, senha.toCharArray());
        }
    }

    /** Arquivo com chave privada: criado com permissão 0600 quando o sistema de arquivos é POSIX. */
    private static OutputStream arquivoPrivado(Path destino) throws IOException {
        Files.deleteIfExists(destino);
        if (destino.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(destino, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        return Files.newOutputStream(destino);
    }

    private static String pem(X509Certificate certificado) throws GeneralSecurityException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificado.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    private static String senhaAleatoria() {
        String alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder senha = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            senha.append(alfabeto.charAt(RANDOM.nextInt(alfabeto.length())));
        }
        return senha.toString();
    }
}
