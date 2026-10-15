/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/**
 * Estado de um servidor local em {@code <base>/<modo>/servidor.properties}: PID, porta, modo, instante de
 * início do processo e comando (identidade do PID, contra reuso) e caminho do log. O diretório é 0700 e os
 * arquivos 0600 (POSIX); a gravação é atômica.
 *
 * @param inicioDoProcesso instante de início do processo segundo o SO (nulo = desconhecido)
 * @param iniciadoEm       instante em que a CLI subiu o servidor (nulo = desconhecido)
 * @param log              arquivo de log do servidor (nulo = desconhecido)
 */
record EstadoDoServidor(Modo modo, long pid, int porta, Instant inicioDoProcesso, Instant iniciadoEm, Path log) {

    static final String ARQUIVO = "servidor.properties";
    static final String LOG = "servidor.log";
    static final String TRAVA = "operacao.lock";

    private static final Set<PosixFilePermission> DIRETORIO = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> PRIVADO = PosixFilePermissions.fromString("rw-------");

    /** Diretório do estado do modo dentro da base, criado com permissões restritas. */
    static Path diretorio(Path base, Modo modo) {
        Path dir = base.toAbsolutePath().normalize().resolve(modo.nome());
        try {
            if (!Files.isDirectory(base)) {
                Files.createDirectories(base);
                restringir(base, DIRETORIO);
            }
            Files.createDirectories(dir);
            restringir(dir, DIRETORIO);
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível criar o diretório de estado " + dir + ": " + e.getMessage());
        }
        return dir;
    }

    /** Estado gravado em {@code dir}, se houver; estado ilegível é erro (nunca se perde um servidor de vista). */
    static Optional<EstadoDoServidor> ler(Path dir) {
        Path arquivo = dir.resolve(ARQUIVO);
        if (!Files.isRegularFile(arquivo)) {
            return Optional.empty();
        }
        Properties propriedades = new Properties();
        try (InputStream in = Files.newInputStream(arquivo)) {
            propriedades.load(in);
            Modo modo = new Modo.Conversor().convert(obrigatoria(propriedades, "modo"));
            return Optional.of(new EstadoDoServidor(modo, Long.parseLong(obrigatoria(propriedades, "pid")),
                    Integer.parseInt(obrigatoria(propriedades, "porta")), instante(propriedades, "inicioDoProcesso"),
                    instante(propriedades, "iniciadoEm"),
                    propriedades.getProperty("log") != null ? Path.of(propriedades.getProperty("log")) : null));
        } catch (IOException | RuntimeException e) {
            throw new FalhaDeUso("Estado do servidor ilegível em " + arquivo + "; se nenhum servidor estiver em "
                    + "execução, remova o arquivo.");
        }
    }

    private static String obrigatoria(Properties propriedades, String nome) {
        return Objects.requireNonNull(propriedades.getProperty(nome), nome);
    }

    private static Instant instante(Properties propriedades, String nome) {
        String valor = propriedades.getProperty(nome);
        try {
            return valor != null ? Instant.parse(valor) : null;
        } catch (DateTimeException e) {
            return null;
        }
    }

    /** Grava atomicamente (temporário 0600 + move) em {@code dir}. */
    void gravar(Path dir) {
        Properties propriedades = new Properties();
        propriedades.setProperty("modo", modo.nome());
        propriedades.setProperty("pid", String.valueOf(pid));
        propriedades.setProperty("porta", String.valueOf(porta));
        if (inicioDoProcesso != null) {
            propriedades.setProperty("inicioDoProcesso", inicioDoProcesso.toString());
        }
        if (iniciadoEm != null) {
            propriedades.setProperty("iniciadoEm", iniciadoEm.toString());
        }
        if (log != null) {
            propriedades.setProperty("log", log.toString());
        }
        Path temporario = dir.resolve(ARQUIVO + ".tmp");
        try {
            criarPrivado(temporario);
            try (OutputStream out = Files.newOutputStream(temporario, StandardOpenOption.TRUNCATE_EXISTING)) {
                propriedades.store(out, "Servidor local do Safira (safira servidor)");
            }
            try {
                Files.move(temporario, dir.resolve(ARQUIVO), StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporario, dir.resolve(ARQUIVO), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Não foi possível gravar o estado do servidor em " + dir, e);
        }
    }

    static void remover(Path dir) {
        try {
            Files.deleteIfExists(dir.resolve(ARQUIVO));
        } catch (IOException e) {
            throw new UncheckedIOException("Não foi possível remover o estado do servidor em " + dir, e);
        }
    }

    /**
     * O processo do estado, se vivo e com identidade confirmada: mesmo instante de início e comando
     * {@code servidor executar --modo <modo>}. Identidade desconhecida (início ou comando indisponíveis)
     * conta como NÃO confirmada: um PID reaproveitado por outro processo nunca é tomado pelo servidor.
     */
    Optional<ProcessHandle> processo() {
        return vivo().filter(this::mesmoProcesso);
    }

    /** O processo com o PID do estado, se vivo, sem conferir a identidade. */
    Optional<ProcessHandle> vivo() {
        return ProcessHandle.of(pid).filter(ProcessHandle::isAlive);
    }

    private boolean mesmoProcesso(ProcessHandle processo) {
        Optional<Instant> inicio = processo.info().startInstant();
        return inicioDoProcesso != null && inicio.isPresent()
                && inicio.get().truncatedTo(ChronoUnit.SECONDS).equals(inicioDoProcesso.truncatedTo(ChronoUnit.SECONDS))
                && comandoDoServidor(processo.info(), modo);
    }

    /** Os argumentos (ou a linha de comando) contêm {@code servidor executar} e {@code --modo <modo>}. */
    static boolean comandoDoServidor(ProcessHandle.Info info, Modo modo) {
        List<String> argumentos = info.arguments().map(List::of)
                .or(() -> info.commandLine().map(linha -> List.of(linha.split("\\s+"))))
                .orElse(List.of());
        return Collections.indexOfSubList(argumentos, List.of("servidor", "executar")) >= 0
                && Collections.indexOfSubList(argumentos, List.of("--modo", modo.nome())) >= 0;
    }

    /** Cria (ou recria vazio) um arquivo 0600. */
    static void criarPrivado(Path arquivo) throws IOException {
        Files.deleteIfExists(arquivo);
        try {
            Files.createFile(arquivo, PosixFilePermissions.asFileAttribute(PRIVADO));
        } catch (UnsupportedOperationException e) {
            Files.createFile(arquivo);
        }
    }

    /** Cria o arquivo 0600 se não existir (nunca recria: a trava pode estar em uso). */
    private static void criarSeAusente(Path arquivo) throws IOException {
        try {
            Files.createFile(arquivo, PosixFilePermissions.asFileAttribute(PRIVADO));
        } catch (FileAlreadyExistsException e) {
            // já existe: mantém
        } catch (UnsupportedOperationException e) {
            if (!Files.exists(arquivo)) {
                Files.createFile(arquivo);
            }
        }
    }

    private static void restringir(Path caminho, Set<PosixFilePermission> permissoes) throws IOException {
        try {
            Files.setPosixFilePermissions(caminho, permissoes);
        } catch (UnsupportedOperationException e) {
            // sem POSIX (ex.: Windows): vale a ACL herdada do diretório do usuário
        }
    }

    /**
     * Trava exclusiva das operações que mudam o estado de {@code dir} (iniciar, parar, limpeza de órfão).
     * Vazio = outra operação em andamento.
     */
    static Optional<Trava> travar(Path dir) {
        try {
            criarSeAusente(dir.resolve(TRAVA));
            FileChannel canal = FileChannel.open(dir.resolve(TRAVA), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            try {
                FileLock trava = canal.tryLock();
                if (trava == null) {
                    canal.close();
                    return Optional.empty();
                }
                return Optional.of(new Trava(canal));
            } catch (OverlappingFileLockException e) {
                canal.close();
                return Optional.empty();
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Não foi possível travar " + dir.resolve(TRAVA), e);
        }
    }

    /** Trava em posse desta operação; liberada ao fechar. */
    record Trava(FileChannel canal) implements AutoCloseable {

        @Override
        public void close() {
            try {
                canal.close();
            } catch (IOException e) {
                // fechar o canal libera a trava; nada a fazer
            }
        }
    }
}
