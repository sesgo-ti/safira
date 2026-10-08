/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Gera uma PKI de simulação (SEM VALOR LEGAL) para o modo {@code safira.simulacao}: raiz, AC
 * intermediária, signatário A3-like e um segundo signatário revogado, LCRs da raiz e da AC e um
 * trecho {@code application-simulacao.yml} com caminhos e allowlist prontos.
 *
 * <p>Uso: {@code --saida <dir> [--senha <senha>] [--politica <oid A3>] [--cpf <11 dígitos>]
 * [--validade-dias <n>]}. Sem {@code --senha}, gera uma senha aleatória e a imprime; a senha
 * informada nunca é impressa. Os PKCS#12 são gravados com permissão 0600 (POSIX).
 */
public final class GeradorPkiSimulada {

    public static final String ALIAS_SIGNATARIO = "signatario";
    public static final String ALIAS_REVOGADO = "revogado";
    public static final String POLITICA_PADRAO = "2.16.76.1.2.3.999";
    public static final String CPF_PADRAO = "52998224725";
    public static final String MARCA = "SIMULACAO - SEM VALOR LEGAL";

    private static final String SAN_CPF_OID = "2.16.76.1.3.1";
    private static final String LCR_BASE = "http://lcr.simulacao.invalid/";
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private static final SecureRandom RANDOM = new SecureRandom();

    private GeradorPkiSimulada() {
    }

    /**
     * Parâmetros da geração.
     *
     * @param senha        senha dos PKCS#12
     * @param politicaOid  OID de política A3 ({@code 2.16.76.1.2.3.n}) no certificado folha
     * @param cpf          CPF do titular (dígitos verificadores válidos)
     * @param validadeDias validade dos certificados folha e das LCRs
     */
    public record Opcoes(String senha, String politicaOid, String cpf, int validadeDias) {

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
            if (validadeDias < 1) {
                throw new IllegalArgumentException("A validade deve ser de ao menos um dia: " + validadeDias);
            }
        }

        public static Opcoes padrao() {
            return new Opcoes(senhaAleatoria(), POLITICA_PADRAO, CPF_PADRAO, 365);
        }

        public Opcoes comSenha(String valor) {
            return new Opcoes(valor, politicaOid, cpf, validadeDias);
        }

        public Opcoes comPoliticaOid(String valor) {
            return new Opcoes(senha, valor, cpf, validadeDias);
        }

        public Opcoes comCpf(String valor) {
            return new Opcoes(senha, politicaOid, valor, validadeDias);
        }

        public Opcoes comValidadeDias(int valor) {
            return new Opcoes(senha, politicaOid, cpf, valor);
        }
    }

    /** Arquivos gerados e valores para a allowlist {@code safira.policy.accepted-certificate-policies}. */
    public record Resultado(Path raiz, Path ac, Path signatario, Path revogado, Path lcrRaiz, Path lcrAc, Path yaml,
                            String senha, String politicaOid, String issuerSha256) {
    }

    public static void main(String[] args) {
        Map<String, String> argumentos = argumentos(args);
        String saida = argumentos.remove("--saida");
        if (saida == null) {
            System.err.println("Uso: GeradorPkiSimulada --saida <dir> [--senha <senha>] [--politica <oid A3>]"
                    + " [--cpf <cpf>] [--validade-dias <n>]");
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
        if (argumentos.containsKey("--validade-dias")) {
            opcoes = opcoes.comValidadeDias(Integer.parseInt(argumentos.remove("--validade-dias")));
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
            Instant agora = Instant.now();
            Instant inicio = agora.minus(Duration.ofHours(1));
            Instant fimFolha = agora.plus(Duration.ofDays(opcoes.validadeDias()));

            KeyPair chavesRaiz = rsa();
            X509Certificate raiz = raiz(chavesRaiz, inicio, agora.plus(Duration.ofDays(3650)));
            KeyPair chavesAc = rsa();
            X509Certificate ac = ac(chavesAc, chavesRaiz, raiz, inicio, agora.plus(Duration.ofDays(1825)));

            KeyPair chavesSignatario = rsa();
            X509Certificate signatario = folha(chavesSignatario, chavesAc, ac, opcoes, "FULANO SIMULADO",
                    inicio, fimFolha);
            KeyPair chavesRevogado = rsa();
            X509Certificate revogado = folha(chavesRevogado, chavesAc, ac, opcoes, "FULANO REVOGADO",
                    inicio, fimFolha);

            Date proxima = Date.from(fimFolha);
            byte[] lcrRaiz = lcr(chavesRaiz, raiz, null, agora, proxima);
            byte[] lcrAc = lcr(chavesAc, ac, revogado, agora, proxima);

            Resultado resultado = new Resultado(dir.resolve("raiz.pem"), dir.resolve("ac.pem"),
                    dir.resolve("signatario.p12"), dir.resolve("revogado.p12"), dir.resolve("lcr-raiz.crl"),
                    dir.resolve("lcr-ac.crl"), dir.resolve("application-simulacao.yml"), opcoes.senha(),
                    opcoes.politicaOid(), IcpBrasilCertificateProfile.sha256Hex(ac));

            Files.writeString(resultado.raiz(), pem(raiz));
            Files.writeString(resultado.ac(), pem(ac));
            p12(resultado.signatario(), ALIAS_SIGNATARIO, chavesSignatario, opcoes.senha(), signatario, ac, raiz);
            p12(resultado.revogado(), ALIAS_REVOGADO, chavesRevogado, opcoes.senha(), revogado, ac, raiz);
            Files.write(resultado.lcrRaiz(), lcrRaiz);
            Files.write(resultado.lcrAc(), lcrAc);
            Files.writeString(resultado.yaml(), yaml(resultado));
            return resultado;
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao gravar a PKI de simulação em " + saida, e);
        } catch (GeneralSecurityException | OperatorCreationException e) {
            throw new IllegalStateException("Falha ao gerar a PKI de simulação", e);
        }
    }

    private static String yaml(Resultado r) {
        return """
                # PKI de simulação (%s) gerada pelo GeradorPkiSimulada.
                # Uso: java -jar safira-rest.jar --spring.profiles.active=simulacao \\
                #        --spring.config.additional-location=file:%s/
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

    private static X509Certificate raiz(KeyPair chaves, Instant inicio, Instant fim) throws IOException,
            GeneralSecurityException, OperatorCreationException {
        X500Name nome = new X500Name("CN=AC Raiz " + MARCA + ",OU=Safira Simulacao,O=" + MARCA + ",C=BR");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(nome, serial(), Date.from(inicio),
                Date.from(fim), nome, chaves.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(chaves.getPublic()));
        return converter(builder.build(assinante(chaves)));
    }

    private static X509Certificate ac(KeyPair chaves, KeyPair chavesRaiz, X509Certificate raiz, Instant inicio,
                                      Instant fim) throws IOException, GeneralSecurityException,
            OperatorCreationException {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(raiz, serial(), Date.from(inicio),
                Date.from(fim), new X500Name("CN=AC " + MARCA + ",OU=Safira Simulacao,O=" + MARCA + ",C=BR"),
                chaves.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(chaves.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(raiz));
        builder.addExtension(Extension.cRLDistributionPoints, false, pontoDistribuicao("lcr-raiz.crl"));
        return converter(builder.build(assinante(chavesRaiz)));
    }

    private static X509Certificate folha(KeyPair chaves, KeyPair chavesAc, X509Certificate ac, Opcoes opcoes,
                                         String nome, Instant inicio, Instant fim) throws IOException,
            GeneralSecurityException, OperatorCreationException {
        X500Name titular = new X500Name("CN=" + nome + " " + MARCA + ":" + opcoes.cpf() + ",SERIALNUMBER="
                + opcoes.cpf() + ",OU=" + MARCA + ",O=" + MARCA + ",C=BR");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(ac, serial(), Date.from(inicio),
                Date.from(fim), titular, chaves.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier(opcoes.politicaOid()))));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        // otherName ICP-Brasil 2.16.76.1.3.1: nascimento DDMMAAAA + CPF + NIS (11) + RG (15) + órgão/UF (6)
        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(SAN_CPF_OID));
        otherName.add(new DERTaggedObject(true, 0, new DERUTF8String("01011990" + opcoes.cpf() + "0".repeat(32))));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(otherName))));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(chaves.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(ac));
        builder.addExtension(Extension.cRLDistributionPoints, false, pontoDistribuicao("lcr-ac.crl"));
        return converter(builder.build(assinante(chavesAc)));
    }

    /** Endereço não roteável ({@code .invalid}, RFC 2606): a revogação vem das LCRs locais. */
    private static CRLDistPoint pontoDistribuicao(String arquivo) {
        GeneralNames url = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, LCR_BASE + arquivo));
        return new CRLDistPoint(new DistributionPoint[]{
                new DistributionPoint(new DistributionPointName(url), null, null)});
    }

    private static byte[] lcr(KeyPair chavesEmissor, X509Certificate emissor, X509Certificate revogado,
                              Instant agora, Date proxima) throws IOException, GeneralSecurityException,
            OperatorCreationException {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(X500Name.getInstance(emissor.getSubjectX500Principal().getEncoded()),
                Date.from(agora));
        builder.setNextUpdate(proxima);
        if (revogado != null) {
            builder.addCRLEntry(revogado.getSerialNumber(), Date.from(agora.minusSeconds(60)), CRLReason.keyCompromise);
        }
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(emissor));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return builder.build(assinante(chavesEmissor)).getEncoded();
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

    private static KeyPair rsa() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private static ContentSigner assinante(KeyPair chaves) throws OperatorCreationException {
        return new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(chaves.getPrivate());
    }

    private static X509Certificate converter(X509CertificateHolder holder) throws GeneralSecurityException {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static BigInteger serial() {
        return new BigInteger(127, RANDOM).add(BigInteger.ONE);
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
