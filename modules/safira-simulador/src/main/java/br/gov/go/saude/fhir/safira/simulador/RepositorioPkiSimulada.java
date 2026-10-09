/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida.Situacao;
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada.Entidade;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada.Material;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

/**
 * Diretório da PKI simulada (SEM VALOR LEGAL) do simulador: gera e grava a PKI na primeira partida e a
 * reutiliza nas seguintes (mesmas raízes, então assinaturas anteriores continuam válidas).
 *
 * <ul>
 *   <li>inexistente ou vazio: gera e grava; o manifesto {@value #MANIFESTO} vai por último, como marca
 *       de completude;</li>
 *   <li>com arquivos: carrega e confere (PKCS#12 legíveis, PEM iguais aos persistidos, cadeia
 *       raiz → AC → folhas); qualquer falha impede a partida com o diretório e o motivo;</li>
 *   <li>signatário vencido ou a menos de {@link #ANTECEDENCIA_RENOVACAO} do vencimento: só a folha é
 *       renovada pela mesma AC (mesma chave), raiz e AC intactas.</li>
 * </ul>
 *
 * <p>Material privado ({@code .p12} e {@value #SENHA}) com permissão 0600 e diretório 0700 quando o
 * sistema de arquivos é POSIX. LCR e OCSP saem da AC carregada a cada partida, com validade de
 * {@link #VALIDADE_REVOGACAO} renovada a cada emissão.
 */
public final class RepositorioPkiSimulada {

    static final String MANIFESTO = "pki.properties";
    static final String SENHA = "senha.txt";
    static final String AUTORIDADES = "autoridades.p12";
    static final String RAIZ = "raiz.pem";
    static final String AC = "ac.pem";
    static final String SIGNATARIO = "signatario.p12";
    static final String REVOGADO = "revogado.p12";
    static final String LCR_RAIZ = "lcr-raiz.crl";
    static final String LCR_AC = "lcr-ac.crl";

    static final Duration ANTECEDENCIA_RENOVACAO = Duration.ofDays(30);
    static final Duration VALIDADE_REVOGACAO = Duration.ofDays(7);

    private static final String FORMATO = "1";
    private static final String ALIAS_RAIZ = "raiz";
    private static final String ALIAS_AC = "ac";
    private static final String ALIAS_TSA = "tsa";
    private static final List<String> OBRIGATORIOS = List.of(MANIFESTO, SENHA, AUTORIDADES, RAIZ, AC, SIGNATARIO, REVOGADO);

    private RepositorioPkiSimulada() {
    }

    /** Gera (diretório inexistente ou vazio) ou carrega a PKI de {@code diretorio}. */
    public static PkiPersistida abrir(Path diretorio) {
        return abrir(diretorio, GeradorPkiSimulada.VALIDADE_FOLHA);
    }

    /** Como {@link #abrir(Path)}, com a validade do signatário de uma PKI nova. */
    static PkiPersistida abrir(Path diretorio, Period validadeFolha) {
        Path dir = diretorio.toAbsolutePath().normalize();
        return vazio(dir) ? gerar(dir, validadeFolha) : carregar(dir);
    }

    private static boolean vazio(Path dir) {
        if (!Files.exists(dir)) {
            return true;
        }
        try (Stream<Path> conteudo = Files.list(dir)) {
            return conteudo.findAny().isEmpty();
        } catch (IOException e) {
            throw new UncheckedIOException("Diretório da PKI simulada ilegível: " + dir, e);
        }
    }

    private static PkiPersistida gerar(Path dir, Period validadeFolha) {
        try {
            Files.createDirectories(dir);
            if (posix(dir)) {
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            }
            Opcoes opcoes = Opcoes.padrao();
            PkiIcpSimulada pki = PkiIcpSimulada.criar(GeradorPkiSimulada.perfil(opcoes).comValidade(validadeFolha));
            Files.writeString(dir.resolve(RAIZ), GeradorPkiSimulada.pem(pki.raiz()));
            Files.writeString(dir.resolve(AC), GeradorPkiSimulada.pem(pki.ac()));
            gravarSignatario(dir, pki, opcoes.senha());
            GeradorPkiSimulada.p12(dir.resolve(REVOGADO), GeradorPkiSimulada.ALIAS_REVOGADO, pki.chavesRevogado(),
                    opcoes.senha(), pki.revogado(), pki.ac(), pki.raiz());
            gravarAutoridades(dir.resolve(AUTORIDADES), pki, opcoes.senha());
            try (OutputStream out = GeradorPkiSimulada.arquivoPrivado(dir.resolve(SENHA))) {
                out.write(opcoes.senha().getBytes(StandardCharsets.UTF_8));
            }
            Properties manifesto = new Properties();
            manifesto.setProperty("formato", FORMATO);
            manifesto.setProperty("politica-oid", opcoes.politicaOid());
            manifesto.setProperty("revogado-em", Long.toString(pki.revogadoEm().getTime()));
            try (OutputStream out = Files.newOutputStream(dir.resolve(MANIFESTO))) {
                manifesto.store(out, "PKI simulada do Safira (" + GeradorPkiSimulada.MARCA + ")");
            }
            // A partir daqui vale o mesmo caminho do reinício: OCSP/LCR com validade curta e renovada.
            return montar(dir, PkiIcpSimulada.restaurar(pki.material(), VALIDADE_REVOGACAO), opcoes.politicaOid(),
                    Situacao.GERADA);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar a PKI simulada em " + dir, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao gerar a PKI simulada em " + dir, e);
        }
    }

    private static PkiPersistida carregar(Path dir) {
        List<String> faltando = OBRIGATORIOS.stream().filter(nome -> !Files.isRegularFile(dir.resolve(nome))).toList();
        if (!faltando.isEmpty()) {
            throw invalida(dir, "incompleta: faltam " + String.join(", ", faltando), null);
        }
        Properties manifesto = new Properties();
        char[] senha;
        Material material;
        try {
            try (InputStream in = Files.newInputStream(dir.resolve(MANIFESTO))) {
                manifesto.load(in);
            }
            if (!FORMATO.equals(manifesto.getProperty("formato"))) {
                throw invalida(dir, "corrompida: " + MANIFESTO + " com formato desconhecido", null);
            }
            senha = Files.readString(dir.resolve(SENHA)).strip().toCharArray();
            KeyStore autoridades = keyStore(dir, AUTORIDADES, senha);
            Entidade raiz = entidade(dir, autoridades, AUTORIDADES, ALIAS_RAIZ, senha);
            Entidade ac = entidade(dir, autoridades, AUTORIDADES, ALIAS_AC, senha);
            Entidade tsa = entidade(dir, autoridades, AUTORIDADES, ALIAS_TSA, senha);
            Entidade signatario = entidade(dir, keyStore(dir, SIGNATARIO, senha), SIGNATARIO,
                    GeradorPkiSimulada.ALIAS_SIGNATARIO, senha);
            Entidade revogado = entidade(dir, keyStore(dir, REVOGADO, senha), REVOGADO,
                    GeradorPkiSimulada.ALIAS_REVOGADO, senha);
            conferirPem(dir, RAIZ, raiz.certificado());
            conferirPem(dir, AC, ac.certificado());
            conferirEmissor(dir, AUTORIDADES, raiz.certificado(), raiz.certificado());
            conferirEmissor(dir, AUTORIDADES, ac.certificado(), raiz.certificado());
            conferirEmissor(dir, AUTORIDADES, tsa.certificado(), ac.certificado());
            conferirEmissor(dir, SIGNATARIO, signatario.certificado(), ac.certificado());
            conferirEmissor(dir, REVOGADO, revogado.certificado(), ac.certificado());
            material = new Material(raiz, ac, signatario, revogado, tsa,
                    new Date(Long.parseLong(manifesto.getProperty("revogado-em", ""))));
        } catch (IOException | NumberFormatException e) {
            throw invalida(dir, "corrompida: " + e.getMessage(), e);
        }

        PkiIcpSimulada pki = PkiIcpSimulada.restaurar(material, VALIDADE_REVOGACAO);
        Situacao situacao = Situacao.REUTILIZADA;
        if (pki.signatario().getNotAfter().toInstant().isBefore(Instant.now().plus(ANTECEDENCIA_RENOVACAO))) {
            pki.renovarSignatario(GeradorPkiSimulada.VALIDADE_FOLHA);
            try {
                gravarSignatario(dir, pki, new String(senha));
            } catch (IOException e) {
                throw new UncheckedIOException("Falha ao regravar " + dir.resolve(SIGNATARIO), e);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Falha ao regravar " + dir.resolve(SIGNATARIO), e);
            }
            situacao = Situacao.FOLHA_RENOVADA;
        }
        return montar(dir, pki, manifesto.getProperty("politica-oid", GeradorPkiSimulada.POLITICA_PADRAO), situacao);
    }

    /** Regrava as LCRs (validade curta) e devolve a PKI persistida. */
    private static PkiPersistida montar(Path dir, PkiIcpSimulada pki, String politicaOid, Situacao situacao) {
        try {
            Files.write(dir.resolve(LCR_RAIZ), pki.lcrDaRaiz());
            Files.write(dir.resolve(LCR_AC), pki.lcr());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar as LCRs da PKI simulada em " + dir, e);
        }
        return new PkiPersistida(dir, dir.resolve(RAIZ), dir.resolve(AC), dir.resolve(SIGNATARIO),
                dir.resolve(REVOGADO), dir.resolve(SENHA), politicaOid,
                IcpBrasilCertificateProfile.sha256Hex(pki.ac()), pki, situacao);
    }

    private static void gravarSignatario(Path dir, PkiIcpSimulada pki, String senha)
            throws IOException, GeneralSecurityException {
        GeradorPkiSimulada.p12(dir.resolve(SIGNATARIO), GeradorPkiSimulada.ALIAS_SIGNATARIO, pki.chavesSignatario(),
                senha, pki.signatario(), pki.ac(), pki.raiz());
    }

    /** Chaves e certificados de raiz, AC e TSA: LCR, OCSP e carimbo do tempo depois do reinício. */
    private static void gravarAutoridades(Path destino, PkiIcpSimulada pki, String senha)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        entrada(keyStore, ALIAS_RAIZ, pki.chavesRaiz(), senha, pki.raiz());
        entrada(keyStore, ALIAS_AC, pki.chavesAc(), senha, pki.ac(), pki.raiz());
        entrada(keyStore, ALIAS_TSA, pki.chavesTsa(), senha, pki.tsa(), pki.ac(), pki.raiz());
        try (OutputStream out = GeradorPkiSimulada.arquivoPrivado(destino)) {
            keyStore.store(out, senha.toCharArray());
        }
    }

    private static void entrada(KeyStore keyStore, String alias, KeyPair chaves, String senha,
                                X509Certificate... cadeia) throws GeneralSecurityException {
        keyStore.setKeyEntry(alias, chaves.getPrivate(), senha.toCharArray(), (Certificate[]) cadeia);
    }

    private static KeyStore keyStore(Path dir, String nome, char[] senha) {
        try (InputStream in = Files.newInputStream(dir.resolve(nome))) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, senha);
            return keyStore;
        } catch (IOException | GeneralSecurityException e) {
            throw invalida(dir, "corrompida: " + nome + " ilegível com a senha de " + SENHA, e);
        }
    }

    private static Entidade entidade(Path dir, KeyStore keyStore, String nome, String alias, char[] senha) {
        try {
            if (keyStore.getEntry(alias, new KeyStore.PasswordProtection(senha))
                    instanceof KeyStore.PrivateKeyEntry entrada
                    && entrada.getCertificate() instanceof X509Certificate certificado) {
                return new Entidade(certificado, entrada.getPrivateKey());
            }
        } catch (GeneralSecurityException e) {
            throw invalida(dir, "corrompida: " + nome + " sem a chave '" + alias + "' legível", e);
        }
        throw invalida(dir, "corrompida: " + nome + " sem a chave '" + alias + "'", null);
    }

    private static void conferirPem(Path dir, String nome, X509Certificate esperado) {
        try (InputStream in = Files.newInputStream(dir.resolve(nome))) {
            if (!esperado.equals(CertificateFactory.getInstance("X.509").generateCertificate(in))) {
                throw invalida(dir, "corrompida: " + nome + " não confere com " + AUTORIDADES, null);
            }
        } catch (IOException | GeneralSecurityException e) {
            throw invalida(dir, "corrompida: " + nome + " ilegível", e);
        }
    }

    private static void conferirEmissor(Path dir, String nome, X509Certificate certificado, X509Certificate emissor) {
        try {
            certificado.verify(emissor.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw invalida(dir, "corrompida: " + nome + " com certificado não emitido por "
                    + emissor.getSubjectX500Principal().getName(), e);
        }
    }

    private static IllegalStateException invalida(Path dir, String motivo, Exception causa) {
        return new IllegalStateException("PKI simulada em " + dir + " " + motivo + ". Restaure o diretório ou "
                + "aponte safira.simulador.diretorio (SAFIRA_SIMULADOR_DIRETORIO) para um diretório vazio — uma PKI "
                + "nova invalida as assinaturas feitas com a anterior.", causa);
    }

    private static boolean posix(Path dir) {
        return dir.getFileSystem().supportedFileAttributeViews().contains("posix");
    }
}
