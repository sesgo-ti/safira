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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
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
    /** Espera máxima pela trava: cobre a geração ou a renovação de outra partida concorrente. */
    static final Duration ESPERA_TRAVA = Duration.ofSeconds(10);

    private static final Duration INTERVALO_TRAVA = Duration.ofMillis(100);

    private static final String FORMATO = "1";
    private static final String ALIAS_RAIZ = "raiz";
    private static final String ALIAS_AC = "ac";
    private static final String ALIAS_TSA = "tsa";
    private static final List<String> PRIVADOS = List.of(SENHA, AUTORIDADES, SIGNATARIO, REVOGADO);
    private static final SecureRandom DESAFIOS = new SecureRandom();
    private static final List<String> OBRIGATORIOS = List.of(MANIFESTO, SENHA, AUTORIDADES, RAIZ, AC, SIGNATARIO, REVOGADO);

    private static final Logger log = LoggerFactory.getLogger(RepositorioPkiSimulada.class);

    private RepositorioPkiSimulada() {
    }

    /** Gera (diretório inexistente ou vazio) ou carrega a PKI de {@code diretorio}. */
    public static PkiPersistida abrir(Path diretorio) {
        return abrir(diretorio, GeradorPkiSimulada.VALIDADE_FOLHA);
    }

    /** Como {@link #abrir(Path)}, com a validade do signatário de uma PKI nova. */
    static PkiPersistida abrir(Path diretorio, Period validadeFolha) {
        return abrir(diretorio, validadeFolha, Instant.now(), caminho -> {
        });
    }

    /**
     * Como {@link #abrir(Path)}: {@code agora} é o instante das conferências de vigência e renovação e
     * {@code antesDePublicar} recebe o que está para ser publicado (diretório ou PKCS#12 temporário).
     */
    static PkiPersistida abrir(Path diretorio, Period validadeFolha, Instant agora, Consumer<Path> antesDePublicar) {
        Path dir = diretorio.toAbsolutePath().normalize();
        // leitura de PKI existente e vigente: trava compartilhada (leitores em paralelo não conflitam)
        Optional<PkiPersistida> lida = travado(dir, true,
                () -> vazio(dir) ? Optional.empty() : carregar(dir, agora, antesDePublicar, false));
        if (lida.isPresent()) {
            return lida.get();
        }
        // gerar ou renovar: trava exclusiva, com o estado conferido de novo sob ela
        return travado(dir, false, () -> Optional.of(vazio(dir) ? gerar(dir, validadeFolha, antesDePublicar)
                : carregar(dir, agora, antesDePublicar, true).orElseThrow())).orElseThrow();
    }

    /** Trava ao lado do diretório (fora dele, para não contar como conteúdo nem sumir na geração). */
    static Path arquivoTrava(Path dir) {
        return dir.resolveSibling(dir.getFileName() + ".lock");
    }

    /**
     * Executa com a trava do diretório: compartilhada para ler uma PKI existente, exclusiva para gerar
     * ou renovar. Quem não obtém a trava tenta de novo a pequenos intervalos por até {@link #ESPERA_TRAVA}
     * e então falha.
     */
    private static Optional<PkiPersistida> travado(Path dir, boolean compartilhada,
                                                   Supplier<Optional<PkiPersistida>> acao) {
        Path trava = arquivoTrava(dir);
        try {
            criarDiretorioPrivado(trava.getParent());
            try (FileChannel canal = FileChannel.open(trava, StandardOpenOption.CREATE, StandardOpenOption.READ,
                    StandardOpenOption.WRITE)) {
                FileLock obtida = tentarTravar(canal, compartilhada);
                if (obtida == null) {
                    throw new IllegalStateException("Diretório da PKI simulada " + dir
                            + " em uso por outra instância após " + ESPERA_TRAVA.toSeconds() + " s de espera (trava "
                            + trava + "): outra partida está gerando ou renovando a PKI. Aguarde e repita, ou use "
                            + "outro diretório (--pki-dir na CLI, safira.simulador.diretorio na configuração).");
                }
                try (FileLock ignorada = obtida) {
                    return acao.get();
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao travar o diretório da PKI simulada " + dir, e);
        }
    }

    /** Trava obtida em até {@link #ESPERA_TRAVA}, ou nula; na mesma JVM a trava sobreposta também espera. */
    private static FileLock tentarTravar(FileChannel canal, boolean compartilhada) throws IOException {
        long limite = System.nanoTime() + ESPERA_TRAVA.toNanos();
        while (true) {
            try {
                FileLock obtida = canal.tryLock(0, Long.MAX_VALUE, compartilhada);
                if (obtida != null) {
                    return obtida;
                }
            } catch (OverlappingFileLockException e) {
                // outra thread desta JVM detém a trava: espera como se fosse outro processo
            }
            if (System.nanoTime() - limite >= 0) {
                return null;
            }
            try {
                Thread.sleep(INTERVALO_TRAVA);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
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

    /**
     * Gera em {@code <dir>.tmp} (0700) e publica com um rename atômico: partida abortada não deixa o
     * diretório parcial (a sobra {@code .tmp} é descartada na próxima geração).
     */
    private static PkiPersistida gerar(Path dir, Period validadeFolha, Consumer<Path> antesDePublicar) {
        Path temporario = dir.resolveSibling(dir.getFileName() + ".tmp");
        try {
            apagar(temporario);
            criarDiretorioPrivado(temporario);
            Opcoes opcoes = Opcoes.padrao();
            PkiIcpSimulada pki = PkiIcpSimulada.criar(GeradorPkiSimulada.perfil(opcoes).comValidade(validadeFolha));
            Files.writeString(temporario.resolve(RAIZ), GeradorPkiSimulada.pem(pki.raiz()));
            Files.writeString(temporario.resolve(AC), GeradorPkiSimulada.pem(pki.ac()));
            gravarSignatario(temporario.resolve(SIGNATARIO), pki, opcoes.senha());
            GeradorPkiSimulada.p12(temporario.resolve(REVOGADO), GeradorPkiSimulada.ALIAS_REVOGADO,
                    pki.chavesRevogado(), opcoes.senha(), pki.revogado(), pki.ac(), pki.raiz());
            gravarAutoridades(temporario.resolve(AUTORIDADES), pki, opcoes.senha());
            try (OutputStream out = GeradorPkiSimulada.arquivoPrivado(temporario.resolve(SENHA))) {
                out.write(opcoes.senha().getBytes(StandardCharsets.UTF_8));
            }
            Properties manifesto = new Properties();
            manifesto.setProperty("formato", FORMATO);
            manifesto.setProperty("politica-oid", opcoes.politicaOid());
            manifesto.setProperty("revogado-em", Long.toString(pki.revogadoEm().getTime()));
            try (OutputStream out = Files.newOutputStream(temporario.resolve(MANIFESTO))) {
                manifesto.store(out, "PKI simulada do Safira (" + GeradorPkiSimulada.MARCA + ")");
            }
            antesDePublicar.accept(temporario);
            publicar(temporario, dir);
            // A partir daqui vale o mesmo caminho do reinício: OCSP/LCR com validade curta e renovada.
            return montar(dir, PkiIcpSimulada.restaurar(pki.material(), VALIDADE_REVOGACAO), opcoes.politicaOid(),
                    Situacao.GERADA);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar a PKI simulada em " + dir, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao gerar a PKI simulada em " + dir, e);
        } finally {
            apagarSemFalhar(temporario);
        }
    }

    /**
     * Troca o diretório (vazio ou inexistente) pelo temporário com um rename atômico. Quando o rename
     * não cabe (ex.: o diretório é um ponto de montagem, ou outro sistema de arquivos), move arquivo a
     * arquivo com o manifesto por último: não é atômico, mas uma interrupção deixa o diretório sem
     * manifesto, que a próxima partida recusa como "incompleta".
     */
    private static void publicar(Path temporario, Path dir) throws IOException {
        try {
            Files.deleteIfExists(dir);
            Files.move(temporario, dir, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            criarDiretorioPrivado(dir);
            try (Stream<Path> arquivos = Files.list(temporario)) {
                for (Path arquivo : arquivos.filter(caminho -> !caminho.endsWith(MANIFESTO)).toList()) {
                    Files.move(arquivo, dir.resolve(arquivo.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            Files.move(temporario.resolve(MANIFESTO), dir.resolve(MANIFESTO), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Carrega e confere a PKI existente. Signatário a renovar: renova só com {@code podeRenovar} (trava
     * exclusiva); sem ela devolve vazio para o chamador repetir sob a trava exclusiva.
     */
    private static Optional<PkiPersistida> carregar(Path dir, Instant agora, Consumer<Path> antesDePublicar,
                                                    boolean podeRenovar) {
        List<String> faltando = OBRIGATORIOS.stream().filter(nome -> !Files.isRegularFile(dir.resolve(nome))).toList();
        if (!faltando.isEmpty()) {
            throw invalida(dir, "incompleta: faltam " + String.join(", ", faltando), null);
        }
        for (String privado : PRIVADOS) {
            conferirPermissoes(dir, privado);
        }
        Properties manifesto = manifesto(dir);
        char[] senha = senha(dir);
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
        conferirVigencia(dir, RAIZ, raiz.certificado(), agora);
        conferirVigencia(dir, AC, ac.certificado(), agora);
        conferirEmissor(dir, AUTORIDADES, raiz.certificado(), raiz.certificado());
        conferirEmissor(dir, AUTORIDADES, ac.certificado(), raiz.certificado());
        conferirEmissor(dir, AUTORIDADES, tsa.certificado(), ac.certificado());
        conferirEmissor(dir, SIGNATARIO, signatario.certificado(), ac.certificado());
        conferirEmissor(dir, REVOGADO, revogado.certificado(), ac.certificado());
        Material material = new Material(raiz, ac, signatario, revogado, tsa, revogadoEm(dir, manifesto));

        PkiIcpSimulada pki = PkiIcpSimulada.restaurar(material, VALIDADE_REVOGACAO);
        Situacao situacao = Situacao.REUTILIZADA;
        if (pki.signatario().getNotAfter().toInstant().isBefore(agora.plus(ANTECEDENCIA_RENOVACAO))) {
            if (!podeRenovar) {
                return Optional.empty();
            }
            pki.renovarSignatario(GeradorPkiSimulada.VALIDADE_FOLHA);
            // Grava ao lado (0600) e troca com rename atômico: interrupção mantém o signatario.p12 anterior.
            Path temporario = dir.resolve(SIGNATARIO + ".tmp");
            try {
                gravarSignatario(temporario, pki, new String(senha));
                antesDePublicar.accept(temporario);
                Files.move(temporario, dir.resolve(SIGNATARIO), StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new UncheckedIOException("Falha ao regravar " + dir.resolve(SIGNATARIO), e);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Falha ao regravar " + dir.resolve(SIGNATARIO), e);
            } finally {
                apagarSemFalhar(temporario);
            }
            situacao = Situacao.FOLHA_RENOVADA;
        }
        return Optional.of(montar(dir, pki, manifesto.getProperty("politica-oid", GeradorPkiSimulada.POLITICA_PADRAO),
                situacao));
    }

    /** Regrava as LCRs (validade curta) e devolve a PKI persistida. */
    private static PkiPersistida montar(Path dir, PkiIcpSimulada pki, String politicaOid, Situacao situacao) {
        try {
            gravarAtomico(dir.resolve(LCR_RAIZ), pki.lcrDaRaiz());
            gravarAtomico(dir.resolve(LCR_AC), pki.lcr());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar as LCRs da PKI simulada em " + dir, e);
        }
        return new PkiPersistida(dir, dir.resolve(RAIZ), dir.resolve(AC), dir.resolve(SIGNATARIO),
                dir.resolve(REVOGADO), dir.resolve(SENHA), politicaOid,
                IcpBrasilCertificateProfile.sha256Hex(pki.ac()), pki, situacao);
    }

    /**
     * Grava num temporário exclusivo e troca com rename atômico: leitores em paralelo (trava
     * compartilhada) regravam as LCRs sem que alguém leia um arquivo pela metade.
     */
    private static void gravarAtomico(Path destino, byte[] conteudo) throws IOException {
        Path temporario = Files.createTempFile(destino.getParent(), destino.getFileName() + ".", ".tmp");
        try {
            Files.write(temporario, conteudo);
            if (Files.getFileStore(temporario).supportsFileAttributeView("posix")) {
                // LCR é pública: mesma permissão de um arquivo comum (o temporário nasce 0600)
                Files.setPosixFilePermissions(temporario, PosixFilePermissions.fromString("rw-r--r--"));
            }
            Files.move(temporario, destino, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporario);
        }
    }

    private static void gravarSignatario(Path destino, PkiIcpSimulada pki, String senha)
            throws IOException, GeneralSecurityException {
        GeradorPkiSimulada.p12(destino, GeradorPkiSimulada.ALIAS_SIGNATARIO, pki.chavesSignatario(),
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

    private static Properties manifesto(Path dir) {
        Properties manifesto = new Properties();
        try (InputStream in = Files.newInputStream(dir.resolve(MANIFESTO))) {
            manifesto.load(in);
        } catch (IOException | IllegalArgumentException e) {
            throw invalida(dir, "corrompida: " + MANIFESTO + " ilegível", e);
        }
        if (!FORMATO.equals(manifesto.getProperty("formato"))) {
            throw invalida(dir, "corrompida: " + MANIFESTO + " com formato desconhecido", null);
        }
        return manifesto;
    }

    private static Date revogadoEm(Path dir, Properties manifesto) {
        try {
            return new Date(Long.parseLong(manifesto.getProperty("revogado-em", "")));
        } catch (NumberFormatException e) {
            throw invalida(dir, "corrompida: " + MANIFESTO + " sem revogado-em válido", e);
        }
    }

    private static char[] senha(Path dir) {
        try {
            return Files.readString(dir.resolve(SENHA)).strip().toCharArray();
        } catch (IOException e) {
            throw invalida(dir, "corrompida: " + SENHA + " ilegível", e);
        }
    }

    /**
     * Material privado acessível a grupo ou outros impede a partida (como o ssh com chave aberta): a
     * correção é do operador ({@code chmod 600}), não automática.
     */
    private static void conferirPermissoes(Path dir, String nome) {
        Path arquivo = dir.resolve(nome);
        if (!posix(dir)) {
            return;
        }
        try {
            Set<PosixFilePermission> permissoes = Files.getPosixFilePermissions(arquivo);
            if (permissoes.stream().anyMatch(permissao -> !permissao.name().startsWith("OWNER_"))) {
                throw new IllegalStateException("PKI simulada em " + dir + " insegura: " + nome + " com permissão "
                        + PosixFilePermissions.toString(permissoes) + " (exigido rw-------). Corrija com: chmod 600 "
                        + arquivo);
            }
        } catch (IOException e) {
            throw invalida(dir, "corrompida: permissões de " + nome + " ilegíveis", e);
        }
    }

    private static void conferirVigencia(Path dir, String nome, X509Certificate certificado, Instant agora) {
        try {
            certificado.checkValidity(Date.from(agora));
        } catch (CertificateException e) {
            throw invalida(dir, "inutilizável: " + nome + " vencido ou ainda não válido (validade "
                    + certificado.getNotBefore().toInstant() + " a " + certificado.getNotAfter().toInstant() + ")", e);
        }
    }

    /** Desafio assinado com a chave privada e verificado com o certificado da mesma entrada. */
    private static void conferirPar(Path dir, String nome, String alias, X509Certificate certificado,
                                    PrivateKey chave) {
        String algoritmo = switch (chave.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw invalida(dir, "corrompida: " + nome + " com chave '" + alias + "' de algoritmo não suportado", null);
        };
        byte[] desafio = new byte[32];
        DESAFIOS.nextBytes(desafio);
        boolean confere;
        try {
            Signature assinatura = Signature.getInstance(algoritmo);
            assinatura.initSign(chave);
            assinatura.update(desafio);
            byte[] assinado = assinatura.sign();
            // pela chave pública: initVerify(Certificate) recusa keyUsage sem digitalSignature (raiz, AC)
            assinatura.initVerify(certificado.getPublicKey());
            assinatura.update(desafio);
            confere = assinatura.verify(assinado);
        } catch (GeneralSecurityException e) {
            throw invalida(dir, "corrompida: " + nome + " com chave privada '" + alias
                    + "' que não corresponde ao certificado", e);
        }
        if (!confere) {
            throw invalida(dir, "corrompida: " + nome + " com chave privada '" + alias
                    + "' que não corresponde ao certificado", null);
        }
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
                conferirPar(dir, nome, alias, certificado, entrada.getPrivateKey());
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

    /** Cria o diretório (e os pais que faltarem) com 0700; sem POSIX, avisa que fica sem restrição. */
    private static void criarDiretorioPrivado(Path dir) throws IOException {
        if (posix(dir)) {
            Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            log.warn("Sistema de arquivos sem permissões POSIX: o material privado da PKI simulada em {} "
                    + "(PKCS#12 e senha.txt) fica sem restrição de acesso.", dir);
            Files.createDirectories(dir);
        }
    }

    private static void apagar(Path caminho) throws IOException {
        if (Files.isDirectory(caminho, LinkOption.NOFOLLOW_LINKS)) {
            try (Stream<Path> conteudo = Files.list(caminho)) {
                for (Path filho : conteudo.toList()) {
                    apagar(filho);
                }
            }
        }
        Files.deleteIfExists(caminho);
    }

    private static void apagarSemFalhar(Path caminho) {
        try {
            apagar(caminho);
        } catch (IOException e) {
            log.warn("Não foi possível apagar o temporário {} da PKI simulada.", caminho, e);
        }
    }

    private static boolean posix(Path dir) {
        return dir.getFileSystem().supportedFileAttributeViews().contains("posix");
    }
}
