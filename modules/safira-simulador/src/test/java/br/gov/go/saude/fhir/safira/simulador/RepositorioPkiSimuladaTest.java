/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.PkiPersistida.Situacao;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class RepositorioPkiSimuladaTest {

    @TempDir
    Path temporario;

    private Path diretorio() {
        return temporario.resolve("pki");
    }

    @Test
    void shouldGeneratePkiOnFirstStart() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());

        assertThat(pki.situacao()).isEqualTo(Situacao.GERADA);
        assertThat(pki.diretorio()).isEqualTo(diretorio().toAbsolutePath().normalize());
        assertThat(diretorio()).isDirectoryContaining("glob:**/raiz.pem").isDirectoryContaining("glob:**/ac.pem")
                .isDirectoryContaining("glob:**/signatario.p12").isDirectoryContaining("glob:**/revogado.p12")
                .isDirectoryContaining("glob:**/autoridades.p12").isDirectoryContaining("glob:**/senha.txt")
                .isDirectoryContaining("glob:**/pki.properties").isDirectoryContaining("glob:**/lcr-raiz.crl")
                .isDirectoryContaining("glob:**/lcr-ac.crl");
        X509Certificate folha = folha(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO);
        assertThat(folha).isEqualTo(pki.pki().signatario());
        folha.verify(pki.pki().ac().getPublicKey());
        assertThat(folha.getNotAfter().toInstant()).isBefore(Instant.now().plus(Duration.ofDays(2 * 366)));
        assertThat(pki.issuerSha256()).isEqualTo(pki.pki().emissorSha256());
    }

    @Test
    void shouldGenerateInExistingEmptyDirectory() throws Exception {
        Files.createDirectories(diretorio());

        assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.GERADA);
    }

    @Test
    void shouldReuseExistingPkiOnRestart() throws Exception {
        PkiPersistida primeira = RepositorioPkiSimulada.abrir(diretorio());
        String senha = Files.readString(primeira.senha());

        PkiPersistida segunda = RepositorioPkiSimulada.abrir(diretorio());

        assertThat(segunda.situacao()).isEqualTo(Situacao.REUTILIZADA);
        assertThat(segunda.pki().cadeia()).isEqualTo(primeira.pki().cadeia());
        assertThat(segunda.pki().tsa()).isEqualTo(primeira.pki().tsa());
        assertThat(segunda.pki().chavesTsa().getPrivate()).isEqualTo(primeira.pki().chavesTsa().getPrivate());
        assertThat(segunda.issuerSha256()).isEqualTo(primeira.issuerSha256());
        assertThat(Files.readString(segunda.senha())).isEqualTo(senha);
        assertThat(segunda.pki().fonteOcsp().getRevocationToken(new CertificateToken(segunda.pki().revogado()),
                new CertificateToken(segunda.pki().ac())).getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(segunda.pki().revogadoEm()).isEqualTo(primeira.pki().revogadoEm());
    }

    @Test
    void shouldFailStartupWhenPkiDirectoryIsCorrupted() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Files.writeString(pki.signatario(), "lixo");

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(pki.diretorio().toString())
                .hasMessageContaining("corrompida")
                .hasMessageContaining("signatario.p12");
    }

    @Test
    void shouldFailWhenPkiDirectoryIsIncomplete() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Files.delete(pki.diretorio().resolve("autoridades.p12"));

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("incompleta")
                .hasMessageContaining("autoridades.p12");
    }

    @Test
    void shouldFailWhenDirectoryHasUnknownContent() throws Exception {
        Files.createDirectories(diretorio());
        Files.writeString(diretorio().resolve("outro.txt"), "x");

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("incompleta")
                .hasMessageContaining("pki.properties");
    }

    @Test
    void shouldFailWhenPublicRootDiffersFromPersistedRoot() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        PkiPersistida outra = RepositorioPkiSimulada.abrir(temporario.resolve("outra"));
        Files.copy(outra.raiz(), pki.raiz(), StandardCopyOption.REPLACE_EXISTING);

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("corrompida")
                .hasMessageContaining("raiz.pem");
    }

    @Test
    void shouldWritePrivateMaterialWithOwnerOnlyPermissions() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));

        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(pki.diretorio()))).isEqualTo("rwx------");
        for (String privado : new String[]{"signatario.p12", "revogado.p12", "autoridades.p12", "senha.txt"}) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(pki.diretorio().resolve(privado))))
                    .isEqualTo("rw-------");
        }
    }

    @Test
    void shouldRenewSignerLeafWhenCloseToExpiry() throws Exception {
        PkiPersistida curta = RepositorioPkiSimulada.abrir(diretorio(), Period.ofDays(10));
        X509Certificate antigo = curta.pki().signatario();
        byte[] dados = "assinado antes da renovação".getBytes(StandardCharsets.UTF_8);
        Signature assinador = Signature.getInstance("SHA256withRSA");
        assinador.initSign(curta.pki().chavesSignatario().getPrivate());
        assinador.update(dados);
        byte[] assinatura = assinador.sign();

        PkiPersistida renovada = RepositorioPkiSimulada.abrir(diretorio());
        PkiPersistida depois = RepositorioPkiSimulada.abrir(diretorio());
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(antigo.getPublicKey());
        verificador.update(dados);

        assertThat(renovada.pki().signatario().getSerialNumber()).isNotEqualTo(antigo.getSerialNumber());
        antigo.verify(renovada.pki().ac().getPublicKey());
        assertThat(verificador.verify(assinatura)).isTrue();

        assertThat(renovada.situacao()).isEqualTo(Situacao.FOLHA_RENOVADA);
        assertThat(renovada.pki().raiz()).isEqualTo(curta.pki().raiz());
        assertThat(renovada.pki().ac()).isEqualTo(curta.pki().ac());
        assertThat(renovada.pki().signatario().getPublicKey()).isEqualTo(curta.pki().signatario().getPublicKey());
        assertThat(renovada.pki().signatario().getNotAfter().toInstant())
                .isAfter(Instant.now().plus(Duration.ofDays(700)));
        assertThat(folha(renovada.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO))
                .isEqualTo(renovada.pki().signatario());
        assertThat(depois.situacao()).isEqualTo(Situacao.REUTILIZADA);
        assertThat(depois.pki().signatario()).isEqualTo(renovada.pki().signatario());
    }

    @Test
    void shouldFailWhenDirectoryIsInUseByAnotherInstance() throws Exception {
        Path trava = RepositorioPkiSimulada.arquivoTrava(diretorio().toAbsolutePath().normalize());

        try (FileChannel canal = FileChannel.open(trava, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock ignorada = canal.lock()) {
            assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("em uso por outra instância")
                    .hasMessageContaining(trava.toString());
        }
        assertThat(diretorio()).doesNotExist();
        assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.GERADA);
    }

    @Test
    void shouldWaitForLockWhenAnotherInstanceReleasesItShortly() throws Exception {
        Path trava = RepositorioPkiSimulada.arquivoTrava(diretorio().toAbsolutePath().normalize());
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (FileChannel canal = FileChannel.open(trava, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            FileLock ocupada = canal.lock();
            Future<Object> liberacao = executor.submit(() -> {
                Thread.sleep(500);
                ocupada.release();
                return null;
            });

            assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.GERADA);
            liberacao.get();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void shouldNeverGenerateTwiceWhenOpenedConcurrently() throws Exception {
        CountDownLatch largada = new CountDownLatch(1);
        Callable<Object> abrir = () -> {
            largada.await();
            try {
                return RepositorioPkiSimulada.abrir(diretorio()).situacao();
            } catch (IllegalStateException e) {
                return e.getMessage();
            }
        };
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Object> primeiro = executor.submit(abrir);
            Future<Object> segundo = executor.submit(abrir);
            largada.countDown();
            List<Object> resultados = List.of(primeiro.get(), segundo.get());

            assertThat(resultados).containsOnlyOnce(Situacao.GERADA);
            assertThat(resultados).allSatisfy(resultado -> assertThat(resultado.toString())
                    .matches("GERADA|REUTILIZADA"));
        } finally {
            executor.shutdownNow();
        }
        assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.REUTILIZADA);
    }

    @Test
    void shouldNotLeavePartialDirectoryWhenGenerationIsAborted() {
        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio(), GeradorPkiSimulada.VALIDADE_FOLHA,
                Instant.now(), RepositorioPkiSimuladaTest::abortar))
                .hasMessageContaining("abortada");

        assertThat(diretorio()).doesNotExist();
        assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.GERADA);
        assertThat(temporario.resolve("pki.tmp")).doesNotExist();
    }

    @Test
    void shouldKeepPreviousSignerWhenRenewalIsAborted() throws Exception {
        PkiPersistida curta = RepositorioPkiSimulada.abrir(diretorio(), Period.ofDays(10));

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio(), GeradorPkiSimulada.VALIDADE_FOLHA,
                Instant.now(), RepositorioPkiSimuladaTest::abortar))
                .hasMessageContaining("abortada");

        assertThat(folha(curta.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO)).isEqualTo(curta.pki().signatario());
        assertThat(RepositorioPkiSimulada.abrir(diretorio()).situacao()).isEqualTo(Situacao.FOLHA_RENOVADA);
    }

    @Test
    void shouldCreateDirectoriesWithOwnerOnlyPermissions() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path aninhado = temporario.resolve("a").resolve("b").resolve("pki");

        RepositorioPkiSimulada.abrir(aninhado);

        for (Path pasta : List.of(temporario.resolve("a"), temporario.resolve("a").resolve("b"), aninhado)) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(pasta))).isEqualTo("rwx------");
        }
    }

    @Test
    void shouldFailWhenPrivateKeyDoesNotMatchCertificate() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        String senha = Files.readString(pki.senha()).strip();
        GeradorPkiSimulada.p12(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO,
                new KeyPair(pki.pki().signatario().getPublicKey(), pki.pki().chavesRevogado().getPrivate()), senha,
                pki.pki().signatario(), pki.pki().ac(), pki.pki().raiz());

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("corrompida")
                .hasMessageContaining("signatario.p12")
                .hasMessageContaining("não corresponde");
    }

    @Test
    void shouldFailWhenPrivateMaterialIsAccessibleByOthers() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Files.setPosixFilePermissions(pki.senha(), PosixFilePermissions.fromString("rw-r--r--"));

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("senha.txt")
                .hasMessageContaining("rw-r--r--")
                .hasMessageContaining("chmod 600");
    }

    @Test
    void shouldFailWhenRootIsExpired() {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Instant depois = pki.pki().raiz().getNotAfter().toInstant().plus(Duration.ofDays(1));

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio(), GeradorPkiSimulada.VALIDADE_FOLHA, depois,
                caminho -> {
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("raiz.pem")
                .hasMessageContaining("vencido");
    }

    @Test
    void shouldFailWhenIntermediateCaIsExpired() {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Instant depois = pki.pki().ac().getNotAfter().toInstant().plus(Duration.ofDays(1));

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio(), GeradorPkiSimulada.VALIDADE_FOLHA, depois,
                caminho -> {
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ac.pem")
                .hasMessageContaining("vencido");
    }

    @Test
    void shouldFailWithFixedMessageWhenManifestIsMalformed() throws Exception {
        PkiPersistida pki = RepositorioPkiSimulada.abrir(diretorio());
        Files.writeString(pki.diretorio().resolve("pki.properties"), "formato=1\nrevogado-em=\\uZZZZ\n");

        assertThatThrownBy(() -> RepositorioPkiSimulada.abrir(diretorio()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("corrompida")
                .hasMessageContaining("pki.properties")
                .hasMessageNotContaining("Malformed")
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    private static void abortar(Path caminho) {
        throw new IllegalStateException("partida abortada ao gravar " + caminho);
    }

    private static X509Certificate folha(Path p12, String alias) throws Exception {
        String senha = Files.readString(p12.resolveSibling("senha.txt")).strip();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            keyStore.load(in, senha.toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }
}
