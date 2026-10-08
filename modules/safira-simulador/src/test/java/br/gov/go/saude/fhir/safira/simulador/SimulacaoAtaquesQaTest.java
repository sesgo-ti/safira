/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QA adversarial do modo simulação: ativação indevida, âncoras/LCRs hostis e fraquezas do gerador.
 * Testes {@code @Disabled("VULN-Sn")} documentam vulnerabilidades ainda não corrigidas.
 */
class SimulacaoAtaquesQaTest {

    @TempDir
    static Path saida;

    static Resultado pki;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraSimulacaoAutoConfiguration.class));

    @BeforeAll
    static void gerar() {
        pki = GeradorPkiSimulada.gerar(saida.resolve("pki"), Opcoes.padrao().comSenha("senha-qa"));
    }

    // ---------------------------------------------------------------- ativação indevida / parcial

    @Test
    void shouldStayDisabledWhenOnlyAnchorsAndCrlsAreSet() {
        runner.withPropertyValues("safira.simulacao.trust-anchors=" + pki.raiz().toUri(),
                        "safira.simulacao.crls[0]=" + pki.lcrAc().toUri())
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(TrustMaterialSource.class);
                    assertThat(context).doesNotHaveBean(CertificateVerifierFactory.class);
                });
    }

    @Test
    void shouldStayDisabledWhenEnabledIsExplicitlyFalse() {
        runner.withPropertyValues("safira.simulacao.enabled=false",
                        "safira.simulacao.trust-anchors=" + pki.raiz().toUri(),
                        "safira.simulacao.crls[0]=" + pki.lcrAc().toUri())
                .run(context -> {
                    assertThat(context).doesNotHaveBean(TrustMaterialSource.class);
                    assertThat(context).doesNotHaveBean(CertificateVerifierFactory.class);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"yes", "1", "on", "y", "enabled", ""})
    void shouldStayDisabledWhenEnabledIsTruthyButNotTrue(String valor) {
        runner.withPropertyValues("safira.simulacao.enabled=" + valor,
                        "safira.simulacao.trust-anchors=" + pki.raiz().toUri())
                .run(context -> assertThat(context).doesNotHaveBean(TrustMaterialSource.class));
    }

    // ---------------------------------------------------------------- âncoras hostis

    @Test
    void shouldFailStartupWhenAnchorIsSelfSignedEndEntity() throws Exception {
        KeyPair chaves = rsa(2048);
        X509Certificate folha = certificado("CN=Folha autoassinada " + GeradorPkiSimulada.MARCA, chaves,
                "CN=Folha autoassinada " + GeradorPkiSimulada.MARCA, chaves.getPrivate(), null, false);
        Path pem = escreverPem("folha-autoassinada.pem", folha);

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + pem.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void shouldFailStartupWhenAnchorBundleMixesRootAndIntermediate() throws Exception {
        Path bundle = saida.resolve("raiz-mais-ac.pem");
        Files.writeString(bundle, Files.readString(pki.raiz()) + Files.readString(pki.ac()));

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + bundle.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void shouldFailStartupWhenAnchorFileIsGarbage() throws Exception {
        Path lixo = Files.write(saida.resolve("lixo.pem"), new byte[]{0x30, (byte) 0x82, 0x7f, 0x00, 0x01});

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + lixo.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void shouldFailStartupWhenAnchorPointsToDirectory() {
        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + saida.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @Disabled("VULN-S1: âncora remota (http:) é baixada no startup — SSRF e raiz de confiança sem integridade")
    void shouldRefuseRemoteAnchorWithoutAnyRequestWhenUrlIsHttp() throws Exception {
        AtomicInteger acessos = new AtomicInteger();
        HttpServer servidor = servir(Files.readAllBytes(pki.raiz()), acessos);
        try {
            String url = "http://127.0.0.1:" + servidor.getAddress().getPort() + "/raiz.pem";
            runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + url)
                    .run(context -> assertThat(context).hasFailed());
            assertThat(acessos.get()).isZero();
        } finally {
            servidor.stop(0);
        }
    }

    @Test
    @Disabled("VULN-S1: LCR remota (http:) é baixada no startup — SSRF fora do DownloadPolicyGuard")
    void shouldRefuseRemoteCrlWithoutAnyRequestWhenUrlIsHttp() throws Exception {
        AtomicInteger acessos = new AtomicInteger();
        HttpServer servidor = servir(Files.readAllBytes(pki.lcrAc()), acessos);
        try {
            String url = "http://127.0.0.1:" + servidor.getAddress().getPort() + "/lcr-ac.crl";
            runner.withPropertyValues("safira.simulacao.enabled=true",
                            "safira.simulacao.trust-anchors=" + pki.raiz().toUri(), "safira.simulacao.crls[0]=" + url)
                    .run(context -> assertThat(context).hasFailed());
            assertThat(acessos.get()).isZero();
        } finally {
            servidor.stop(0);
        }
    }

    @Test
    @Disabled("VULN-S2: qualquer AC raiz autoassinada vira âncora, inclusive uma raiz ICP-Brasil real ou sósia")
    void shouldFailStartupWhenAnchorIsNotMarkedAsSimulation() throws Exception {
        KeyPair chaves = rsa(2048);
        String nome = "CN=Autoridade Certificadora Raiz Brasileira v10,OU=Instituto Nacional de Tecnologia da Informacao"
                + " - ITI,O=ICP-Brasil,C=BR";
        X509Certificate sosia = certificado(nome, chaves, nome, chaves.getPrivate(), null, true);
        Path pem = escreverPem("sosia-icp.pem", sosia);

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + pem.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @Disabled("VULN-S3: âncora simulada com RSA-512 é aceita — a raiz pode ser fatorada e a PKI forjada")
    void shouldFailStartupWhenAnchorKeyIsWeak() throws Exception {
        KeyPair fraca = rsa(512);
        String nome = "CN=Raiz fraca " + GeradorPkiSimulada.MARCA + ",C=BR";
        X509Certificate raiz = certificado(nome, fraca, nome, fraca.getPrivate(), null, true);
        Path pem = escreverPem("raiz-fraca.pem", raiz);

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + pem.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @Disabled("VULN-S3: âncora simulada vencida é aceita no startup (falha só por requisição)")
    void shouldFailStartupWhenAnchorIsExpired() throws Exception {
        KeyPair chaves = rsa(2048);
        String nome = "CN=Raiz vencida " + GeradorPkiSimulada.MARCA + ",C=BR";
        Instant agora = Instant.now();
        X509Certificate raiz = certificado(nome, chaves, nome, chaves.getPrivate(), null, true,
                agora.minus(Duration.ofDays(30)), agora.minus(Duration.ofDays(1)));
        Path pem = escreverPem("raiz-vencida.pem", raiz);

        runner.withPropertyValues("safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + pem.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    // ---------------------------------------------------------------- LCRs hostis (decisão em tempo de requisição)

    @Test
    void shouldNotPassRevokedLeafWhenIssuerCrlIsMissing() {
        runner.withPropertyValues(habilitado()).withPropertyValues("safira.simulacao.crls[0]=" + pki.lcrRaiz().toUri())
                .run(context -> {
                    X509Certificate revogado = folha(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO);
                    assertThat(indicacao(context.getBean(CertificateVerifierFactory.class), revogado))
                            .isNotEqualTo(Indication.PASSED);
                });
    }

    @Test
    void shouldNotPassLeafWhenIssuerCrlIsForgedByAnotherKey() throws Exception {
        X509Certificate ac = certificadoPem(pki.ac());
        KeyPair atacante = rsa(2048);
        Instant agora = Instant.now();
        Path forjada = Files.write(saida.resolve("lcr-forjada.crl"), lcr(ac, atacante.getPrivate(),
                agora.minusSeconds(60), agora.plus(Duration.ofDays(30)), null));

        runner.withPropertyValues(habilitado())
                .withPropertyValues("safira.simulacao.crls[0]=" + pki.lcrRaiz().toUri(),
                        "safira.simulacao.crls[1]=" + forjada.toUri())
                .run(context -> {
                    X509Certificate revogado = folha(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO);
                    assertThat(indicacao(context.getBean(CertificateVerifierFactory.class), revogado))
                            .isNotEqualTo(Indication.PASSED);
                });
    }

    @Test
    @Disabled("VULN-S4: LCR forjada (assinatura de outra chave) é aceita no startup sem conferência do emissor")
    void shouldFailStartupWhenCrlIsNotSignedByAnyConfiguredCa() throws Exception {
        X509Certificate ac = certificadoPem(pki.ac());
        KeyPair atacante = rsa(2048);
        Instant agora = Instant.now();
        Path forjada = Files.write(saida.resolve("lcr-forjada-startup.crl"), lcr(ac, atacante.getPrivate(),
                agora.minusSeconds(60), agora.plus(Duration.ofDays(30)), null));

        runner.withPropertyValues(habilitado()).withPropertyValues("safira.simulacao.crls[0]=" + forjada.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void shouldNotPassLeafWhenOnlyCrlIsExpired() throws Exception {
        MiniPki mini = MiniPki.criar();
        Instant agora = Instant.now();
        Path vencida = Files.write(saida.resolve("lcr-vencida.crl"), lcr(mini.ac, mini.chavesAc.getPrivate(),
                agora.minus(Duration.ofDays(30)), agora.minus(Duration.ofDays(1)), null));
        Path lcrRaiz = Files.write(saida.resolve("mini-lcr-raiz.crl"), lcr(mini.raiz, mini.chavesRaiz.getPrivate(),
                agora.minusSeconds(60), agora.plus(Duration.ofDays(30)), null));

        runner.withPropertyValues("safira.simulacao.enabled=true",
                        "safira.simulacao.trust-anchors=" + escreverPem("mini-raiz.pem", mini.raiz).toUri(),
                        "safira.simulacao.crls[0]=" + lcrRaiz.toUri(), "safira.simulacao.crls[1]=" + vencida.toUri())
                .run(context -> assertThat(indicacao(context.getBean(CertificateVerifierFactory.class), mini.folha,
                        mini.raiz, mini.ac)).isNotEqualTo(Indication.PASSED));
    }

    @Test
    @Disabled("VULN-S4: LCR vencida (nextUpdate no passado) é aceita no startup sem aviso")
    void shouldFailStartupWhenCrlIsExpired() throws Exception {
        MiniPki mini = MiniPki.criar();
        Instant agora = Instant.now();
        Path vencida = Files.write(saida.resolve("lcr-vencida-startup.crl"), lcr(mini.ac, mini.chavesAc.getPrivate(),
                agora.minus(Duration.ofDays(30)), agora.minus(Duration.ofDays(1)), null));

        runner.withPropertyValues("safira.simulacao.enabled=true",
                        "safira.simulacao.trust-anchors=" + escreverPem("mini-raiz-2.pem", mini.raiz).toUri(),
                        "safira.simulacao.crls[0]=" + vencida.toUri())
                .run(context -> assertThat(context).hasFailed());
    }

    // ---------------------------------------------------------------- gerador

    @Test
    void shouldUseStrongKeysAndUniqueSerialsWhenGenerating() throws Exception {
        X509Certificate raiz = certificadoPem(pki.raiz());
        X509Certificate ac = certificadoPem(pki.ac());
        X509Certificate signatario = folha(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO);
        X509Certificate revogado = folha(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO);
        List<X509Certificate> todos = List.of(raiz, ac, signatario, revogado);

        Set<BigInteger> seriais = new HashSet<>();
        todos.forEach(c -> seriais.add(c.getSerialNumber()));
        assertThat(seriais).hasSize(4).allMatch(s -> s.signum() > 0 && s.bitLength() >= 64 && s.bitLength() <= 159);
        assertThat(todos).allMatch(c -> ((RSAPublicKey) c.getPublicKey()).getModulus().bitLength() >= 2048);
        assertThat(todos).allMatch(c -> c.getSigAlgName().toUpperCase().startsWith("SHA256"));
    }

    @Test
    void shouldGenerateDistinctPkiOnEachRun(@TempDir Path outra) throws Exception {
        Resultado segunda = GeradorPkiSimulada.gerar(outra, Opcoes.padrao().comSenha("senha-qa"));

        assertThat(certificadoPem(segunda.raiz()).getPublicKey()).isNotEqualTo(certificadoPem(pki.raiz()).getPublicKey());
        assertThat(segunda.issuerSha256()).isNotEqualTo(pki.issuerSha256());
    }

    @Test
    void shouldGenerateRandomPasswordsThatDifferWhenNoneIsGiven() {
        String a = Opcoes.padrao().senha();
        String b = Opcoes.padrao().senha();

        assertThat(a).hasSize(20).isNotEqualTo(b);
    }

    @Test
    void shouldMarkEveryCertificateAsSimulationWhenGenerating() throws Exception {
        List<X509Certificate> todos = List.of(certificadoPem(pki.raiz()), certificadoPem(pki.ac()),
                folha(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO),
                folha(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO));

        assertThat(todos).allMatch(c -> c.getSubjectX500Principal().getName().contains(GeradorPkiSimulada.MARCA));
    }

    @Test
    void shouldKeepCrlNextUpdateAfterThisUpdateWhenGenerating() throws Exception {
        X509CRL lcrAc = lcrArquivo(pki.lcrAc());
        X509CRL lcrRaiz = lcrArquivo(pki.lcrRaiz());

        assertThat(lcrAc.getNextUpdate()).isAfter(lcrAc.getThisUpdate()).isAfter(new Date());
        assertThat(lcrRaiz.getNextUpdate()).isAfter(lcrRaiz.getThisUpdate()).isAfter(new Date());
    }

    @Test
    @Disabled("VULN-S5: PKCS#12 com chave privada gravado com as permissões do umask (legível por grupo/outros)")
    void shouldWritePrivateKeyContainersReadableOnlyByOwner() throws Exception {
        Set<PosixFilePermission> permissoes = Files.getPosixFilePermissions(pki.signatario());

        assertThat(permissoes).doesNotContain(PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ,
                PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);
        assertThat(Files.getPosixFilePermissions(pki.revogado()))
                .doesNotContain(PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);
    }

    @Test
    @Disabled("VULN-S5: senha informada por --senha é ecoada no stdout (vaza em logs de CI)")
    void shouldNotEchoPasswordWhenGivenOnCommandLine(@TempDir Path destino) {
        ByteArrayOutputStream capturado = new ByteArrayOutputStream();
        PrintStream original = System.out;
        System.setOut(new PrintStream(capturado, true, StandardCharsets.UTF_8));
        try {
            GeradorPkiSimulada.main(new String[]{"--saida", destino.toString(), "--senha", "SenhaSecretaDoOperador"});
        } finally {
            System.setOut(original);
        }

        assertThat(capturado.toString(StandardCharsets.UTF_8)).doesNotContain("SenhaSecretaDoOperador");
    }

    @Test
    @Disabled("VULN-S6: --validade-dias grande gera folha que vence depois da AC (cadeia mal aninhada)")
    void shouldNotIssueLeafOutlivingIssuerWhenValidityIsLarge(@TempDir Path destino) throws Exception {
        Resultado longo = GeradorPkiSimulada.gerar(destino, Opcoes.padrao().comSenha("senha-qa").comValidadeDias(4000));
        X509Certificate ac = certificadoPem(longo.ac());
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(longo.signatario())) {
            keyStore.load(in, "senha-qa".toCharArray());
        }
        X509Certificate folha = (X509Certificate) keyStore.getCertificate(GeradorPkiSimulada.ALIAS_SIGNATARIO);

        assertThat(folha.getNotAfter()).isBeforeOrEqualTo(ac.getNotAfter());
    }

    // ---------------------------------------------------------------- utilitários

    private static String[] habilitado() {
        return new String[]{"safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + pki.raiz().toUri(),
                "safira.simulacao.intermediates=" + pki.ac().toUri()};
    }

    private static Indication indicacao(CertificateVerifierFactory factory, X509Certificate folha) throws Exception {
        return indicacao(factory, folha, certificadoPem(pki.raiz()), certificadoPem(pki.ac()));
    }

    private static Indication indicacao(CertificateVerifierFactory factory, X509Certificate folha, X509Certificate raiz,
                                        X509Certificate ac) {
        CommonCertificateVerifier verifier = factory.create(CertificateVerifierFactory.acervo(List.of(raiz), List.of(ac)),
                List.of());
        SimpleCertificateReport relatorio = new CertificateValidationService().validate(folha, List.of(), verifier)
                .getSimpleReport();
        return relatorio.getCertificateIndication(new CertificateToken(folha).getDSSIdAsString());
    }

    private static X509Certificate folha(Path p12, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            keyStore.load(in, "senha-qa".toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    private static X509Certificate certificadoPem(Path pem) throws Exception {
        try (InputStream in = Files.newInputStream(pem)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static X509CRL lcrArquivo(Path arquivo) throws Exception {
        try (InputStream in = Files.newInputStream(arquivo)) {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
        }
    }

    private static Path escreverPem(String nome, X509Certificate certificado) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificado.getEncoded());
        return Files.writeString(saida.resolve(nome), "-----BEGIN CERTIFICATE-----\n" + base64
                + "\n-----END CERTIFICATE-----\n");
    }

    private static HttpServer servir(byte[] conteudo, AtomicInteger acessos) throws Exception {
        HttpServer servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        servidor.createContext("/", troca -> {
            acessos.incrementAndGet();
            troca.sendResponseHeaders(200, conteudo.length);
            troca.getResponseBody().write(conteudo);
            troca.close();
        });
        servidor.start();
        return servidor;
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificado(String titular, KeyPair chaves, String emissor, PrivateKey chaveEmissor,
                                               X509Certificate certEmissor, boolean ca) throws Exception {
        Instant agora = Instant.now();
        return certificado(titular, chaves, emissor, chaveEmissor, certEmissor, ca, agora.minus(Duration.ofHours(1)),
                agora.plus(Duration.ofDays(365)));
    }

    private static X509Certificate certificado(String titular, KeyPair chaves, String emissor, PrivateKey chaveEmissor,
                                               X509Certificate certEmissor, boolean ca, Instant inicio, Instant fim)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(emissor),
                new BigInteger(127, new SecureRandom()).add(BigInteger.ONE), Date.from(inicio),
                Date.from(fim), new X500Name(titular), chaves.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        }
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(chaves.getPublic()));
        if (certEmissor != null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(certEmissor));
            GeneralNames url = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                    "http://lcr.simulacao.invalid/qa.crl"));
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{
                    new DistributionPoint(new DistributionPointName(url), null, null)}));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(chaveEmissor)));
    }

    private static byte[] lcr(X509Certificate emissor, PrivateKey chave, Instant inicio, Instant proxima,
                              X509Certificate revogado) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                X500Name.getInstance(emissor.getSubjectX500Principal().getEncoded()), Date.from(inicio));
        builder.setNextUpdate(Date.from(proxima));
        if (revogado != null) {
            builder.addCRLEntry(revogado.getSerialNumber(), Date.from(inicio), CRLReason.keyCompromise);
        }
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(emissor));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.TWO));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(chave)).getEncoded();
    }

    /** PKI mínima com as chaves das ACs expostas, para forjar LCRs. */
    private record MiniPki(KeyPair chavesRaiz, X509Certificate raiz, KeyPair chavesAc, X509Certificate ac,
                           X509Certificate folha) {

        static MiniPki criar() throws Exception {
            KeyPair chavesRaiz = rsa(2048);
            String nomeRaiz = "CN=Mini Raiz " + GeradorPkiSimulada.MARCA + ",C=BR";
            X509Certificate raiz = certificado(nomeRaiz, chavesRaiz, nomeRaiz, chavesRaiz.getPrivate(), null, true);
            KeyPair chavesAc = rsa(2048);
            String nomeAc = "CN=Mini AC " + GeradorPkiSimulada.MARCA + ",C=BR";
            X509Certificate ac = certificado(nomeAc, chavesAc, nomeRaiz, chavesRaiz.getPrivate(), raiz, true);
            KeyPair chavesFolha = rsa(2048);
            X509Certificate folha = certificado("CN=Mini Folha " + GeradorPkiSimulada.MARCA + ",C=BR", chavesFolha,
                    nomeAc, chavesAc.getPrivate(), ac, false);
            return new MiniPki(chavesRaiz, raiz, chavesAc, ac, folha);
        }
    }
}
