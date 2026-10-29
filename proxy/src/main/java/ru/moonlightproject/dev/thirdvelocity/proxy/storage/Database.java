/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ru.moonlightproject.dev.thirdvelocity.proxy.storage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * JDBC access on dedicated worker threads. Each worker owns one connection that is reopened
 * after failures. SQLite uses a single worker; MySQL/MariaDB/PostgreSQL use a small pool.
 */
public final class Database implements AutoCloseable {

  /** SQL flavour. */
  public enum Dialect {
    SQLITE, MYSQL, POSTGRESQL
  }

  /** Work executed with a connection. */
  @FunctionalInterface
  public interface Work<T> {
    /**
     * Runs the work.
     *
     * @param connection connection
     * @return result
     * @throws SQLException on database errors
     */
    T run(Connection connection) throws SQLException;
  }

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  private final Dialect dialect;
  private final String url;
  private final Properties properties;
  private final Driver driver;
  private final ExecutorService executor;
  private final ThreadLocal<Connection> connection = new ThreadLocal<>();
  private final java.util.Set<Connection> opened = java.util.concurrent.ConcurrentHashMap.newKeySet();

  /**
   * Opens the database.
   *
   * @param configuredUrl {@code sqlite:path}, {@code mysql://...}, {@code mariadb://...},
   *     {@code postgresql://...} or a full {@code jdbc:} URL
   * @param user user name (ignored by SQLite)
   * @param password password (ignored by SQLite)
   * @param poolSize workers for network databases
   * @param baseDir directory for relative SQLite paths
   * @throws SQLException if the driver is missing or the schema cannot be created
   */
  public Database(String configuredUrl, String user, String password, int poolSize, Path baseDir)
      throws SQLException {
    String raw = configuredUrl.trim();
    String jdbc = raw.startsWith("jdbc:") ? raw : "jdbc:" + raw;
    String lower = jdbc.toLowerCase(Locale.ROOT);
    String driverClass;
    if (lower.startsWith("jdbc:sqlite:")) {
      dialect = Dialect.SQLITE;
      driverClass = "org.sqlite.JDBC";
      String file = jdbc.substring("jdbc:sqlite:".length());
      Path path = Path.of(file);
      if (!path.isAbsolute()) {
        path = baseDir.resolve(file);
      }
      try {
        Files.createDirectories(path.toAbsolutePath().getParent());
      } catch (java.io.IOException e) {
        throw new SQLException("Cannot create database directory", e);
      }
      jdbc = "jdbc:sqlite:" + path.toAbsolutePath();
      poolSize = 1;
    } else if (lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:")) {
      dialect = Dialect.MYSQL;
      driverClass = "org.mariadb.jdbc.Driver";
      if (lower.startsWith("jdbc:mysql:")) {
        jdbc = "jdbc:mariadb:" + jdbc.substring("jdbc:mysql:".length());
      }
    } else if (lower.startsWith("jdbc:postgresql:")) {
      dialect = Dialect.POSTGRESQL;
      driverClass = "org.postgresql.Driver";
    } else {
      throw new SQLException("Unsupported storage.url, use sqlite:, mysql://, mariadb:// or postgresql://");
    }
    this.url = jdbc;
    this.properties = new Properties();
    if (dialect != Dialect.SQLITE) {
      if (!user.isEmpty()) {
        properties.setProperty("user", user);
      }
      if (!password.isEmpty()) {
        properties.setProperty("password", password);
      }
    }
    try {
      this.driver = (Driver) Class.forName(driverClass, true, Database.class.getClassLoader())
          .getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new SQLException("JDBC driver " + driverClass + " is not available", e);
    }
    AtomicInteger counter = new AtomicInteger();
    this.executor = Executors.newFixedThreadPool(Math.max(1, poolSize), runnable -> {
      Thread thread = new Thread(runnable, "ThirdVelocity-DB-" + counter.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    });
    try {
      call(this::migrate).join();
    } catch (RuntimeException e) {
      executor.shutdownNow();
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw cause instanceof SQLException sql ? sql : new SQLException(cause);
    }
  }

  /**
   * Returns the SQL dialect.
   *
   * @return dialect
   */
  public Dialect dialect() {
    return dialect;
  }

  /**
   * Runs work on a database worker.
   *
   * @param work work
   * @param <T> result type
   * @return future result
   */
  public <T> CompletableFuture<T> call(Work<T> work) {
    return CompletableFuture.supplyAsync(() -> {
      try {
        return work.run(connection());
      } catch (SQLException e) {
        dropConnection();
        throw new java.util.concurrent.CompletionException(e);
      }
    }, executor);
  }

  private Connection connection() throws SQLException {
    Connection current = connection.get();
    if (current != null && !current.isClosed() && (dialect == Dialect.SQLITE || current.isValid(2))) {
      return current;
    }
    dropConnection();
    Connection opened = driver.connect(url, properties);
    if (opened == null) {
      throw new SQLException("Driver rejected URL");
    }
    if (dialect == Dialect.SQLITE) {
      try (Statement statement = opened.createStatement()) {
        statement.execute("PRAGMA journal_mode=WAL");
        statement.execute("PRAGMA synchronous=NORMAL");
        statement.execute("PRAGMA busy_timeout=5000");
      }
    }
    connection.set(opened);
    this.opened.add(opened);
    return opened;
  }

  private void dropConnection() {
    Connection current = connection.get();
    connection.remove();
    if (current != null) {
      opened.remove(current);
      try {
        current.close();
      } catch (SQLException ignored) {
        // Already broken.
      }
    }
  }

  private Void migrate(Connection c) throws SQLException {
    String id = switch (dialect) {
      case SQLITE -> "id INTEGER PRIMARY KEY AUTOINCREMENT";
      case MYSQL -> "id BIGINT AUTO_INCREMENT PRIMARY KEY";
      case POSTGRESQL -> "id BIGSERIAL PRIMARY KEY";
    };
    try (Statement s = c.createStatement()) {
      s.execute("CREATE TABLE IF NOT EXISTS tv_bans (" + id + ", kind VARCHAR(16) NOT NULL,"
          + " target VARCHAR(64) NOT NULL, reason VARCHAR(512) NOT NULL, actor VARCHAR(64) NOT NULL,"
          + " created_at BIGINT NOT NULL, expires_at BIGINT NULL, revoked_at BIGINT NULL,"
          + " revoked_by VARCHAR(64) NULL, updated_at BIGINT NOT NULL)");
      s.execute("CREATE TABLE IF NOT EXISTS tv_seen (name_lc VARCHAR(32) NOT NULL, ip VARCHAR(45) NOT NULL,"
          + " name VARCHAR(32) NOT NULL, subnet VARCHAR(50) NOT NULL, asn BIGINT NOT NULL,"
          + " first_seen BIGINT NOT NULL, last_seen BIGINT NOT NULL, logins BIGINT NOT NULL,"
          + " authenticated INT NOT NULL, PRIMARY KEY (name_lc, ip))");
      s.execute("CREATE TABLE IF NOT EXISTS tv_fingerprints (fingerprint VARCHAR(64) NOT NULL,"
          + " name_lc VARCHAR(32) NOT NULL, first_seen BIGINT NOT NULL, last_seen BIGINT NOT NULL,"
          + " PRIMARY KEY (fingerprint, name_lc))");
      createIndex(s, "tv_bans_updated", "tv_bans", "updated_at");
      createIndex(s, "tv_bans_target", "tv_bans", "kind, target");
      createIndex(s, "tv_seen_ip", "tv_seen", "ip");
      createIndex(s, "tv_seen_subnet", "tv_seen", "subnet");
      createIndex(s, "tv_seen_last", "tv_seen", "last_seen");
      createIndex(s, "tv_fp_name", "tv_fingerprints", "name_lc");
    }
    return null;
  }

  private void createIndex(Statement s, String name, String table, String columns) throws SQLException {
    if (dialect == Dialect.MYSQL) {
      try {
        s.execute("CREATE INDEX " + name + " ON " + table + " (" + columns + ")");
      } catch (SQLException e) {
        // MySQL has no IF NOT EXISTS for indexes; error 1061 means it already exists.
        if (e.getErrorCode() != 1061) {
          throw e;
        }
      }
    } else {
      s.execute("CREATE INDEX IF NOT EXISTS " + name + " ON " + table + " (" + columns + ")");
    }
  }

  /**
   * Returns the upsert clause for {@code tv_seen}-style tables.
   *
   * @param conflictColumns primary key columns
   * @param updates assignments using {@code NEW(column)} for the inserted value
   * @return SQL fragment
   */
  public String upsert(String conflictColumns, String updates) {
    if (dialect == Dialect.MYSQL) {
      return " ON DUPLICATE KEY UPDATE " + updates.replaceAll("NEW\\((\\w+)\\)", "VALUES($1)");
    }
    return " ON CONFLICT (" + conflictColumns + ") DO UPDATE SET "
        + updates.replaceAll("NEW\\((\\w+)\\)", "excluded.$1");
  }

  @Override
  public void close() {
    executor.shutdown();
    try {
      if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
        LOGGER.warn("[x] db       » потоки БД не завершились вовремя");
        executor.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    for (Connection c : opened) {
      try {
        c.close();
      } catch (SQLException ignored) {
        // Shutting down.
      }
    }
    opened.clear();
  }
}
