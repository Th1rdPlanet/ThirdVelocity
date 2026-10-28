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

package ru.moonlightproject.dev.thirdvelocity.proxy.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import org.jspecify.annotations.Nullable;

/** Small HTTP downloader with size limits and archive unpacking. */
public final class Downloader {

  /** How the downloaded body is stored. */
  public enum Format {
    /** Store as is. */
    RAW,
    /** Gunzip. */
    GZIP,
    /** Gunzip and extract the first entry whose name ends with {@code entrySuffix}. */
    TAR_GZ
  }

  private final HttpClient client;
  private final String userAgent;

  /**
   * Creates the downloader.
   *
   * @param userAgent User-Agent header
   */
  public Downloader(String userAgent) {
    this.userAgent = userAgent;
    this.client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(15))
        .build();
  }

  /**
   * Expands {@code {yyyy}}, {@code {mm}} and {@code {yyyy-mm}} with the given month.
   *
   * @param url URL template
   * @param month month
   * @return URL
   */
  public static String expand(String url, YearMonth month) {
    return url.replace("{yyyy}", String.format(Locale.ROOT, "%04d", month.getYear()))
        .replace("{mm}", String.format(Locale.ROOT, "%02d", month.getMonthValue()));
  }

  /**
   * Returns the current UTC month.
   *
   * @return month
   */
  public static YearMonth currentMonth() {
    return YearMonth.now(ZoneOffset.UTC);
  }

  /**
   * Downloads {@code url} into {@code target} atomically.
   *
   * @param url URL
   * @param target destination file
   * @param format body format
   * @param entrySuffix archive entry suffix for {@link Format#TAR_GZ}
   * @param basicAuth {@code user:password} or {@code null}
   * @param maxBytes maximum decoded size
   * @return HTTP status (200 on success; 404 is returned, not thrown)
   * @throws IOException on transport errors, other statuses or oversize bodies
   * @throws InterruptedException if interrupted
   */
  public int download(String url, Path target, Format format, @Nullable String entrySuffix,
      @Nullable String basicAuth, long maxBytes) throws IOException, InterruptedException {
    HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
        .timeout(Duration.ofMinutes(5))
        .header("User-Agent", userAgent)
        .GET();
    if (basicAuth != null && !basicAuth.isBlank()) {
      request.header("Authorization", "Basic "
          + Base64.getEncoder().encodeToString(basicAuth.getBytes(StandardCharsets.UTF_8)));
    }
    HttpResponse<InputStream> response = client.send(request.build(),
        HttpResponse.BodyHandlers.ofInputStream());
    try (InputStream body = response.body()) {
      if (response.statusCode() == 404) {
        return 404;
      }
      if (response.statusCode() != 200) {
        throw new IOException("HTTP " + response.statusCode() + " for " + redact(url));
      }
      Files.createDirectories(target.toAbsolutePath().getParent());
      Path temp = Files.createTempFile(target.toAbsolutePath().getParent(), ".download-", ".tmp");
      try {
        try (InputStream decoded = decode(new BufferedInputStream(body), format, entrySuffix);
            OutputStream out = Files.newOutputStream(temp)) {
          copyLimited(decoded, out, maxBytes);
        }
        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      } finally {
        Files.deleteIfExists(temp);
      }
      return 200;
    }
  }

  private static InputStream decode(InputStream in, Format format, @Nullable String suffix) throws IOException {
    return switch (format) {
      case RAW -> in;
      case GZIP -> new GZIPInputStream(in);
      case TAR_GZ -> tarEntry(new GZIPInputStream(in), suffix == null ? "" : suffix);
    };
  }

  /** Minimal ustar reader: skips entries until one ends with the suffix. */
  private static InputStream tarEntry(InputStream tar, String suffix) throws IOException {
    byte[] header = new byte[512];
    while (true) {
      if (tar.readNBytes(header, 0, 512) < 512) {
        throw new IOException("Archive has no entry ending with " + suffix);
      }
      boolean empty = true;
      for (byte b : header) {
        if (b != 0) {
          empty = false;
          break;
        }
      }
      if (empty) {
        throw new IOException("Archive has no entry ending with " + suffix);
      }
      String name = cString(header, 0, 100);
      String prefix = cString(header, 345, 155);
      String full = prefix.isEmpty() ? name : prefix + "/" + name;
      String sizeField = cString(header, 124, 12).trim();
      long size = sizeField.isEmpty() ? 0 : Long.parseLong(sizeField, 8);
      char type = (char) header[156];
      if ((type == '0' || type == 0) && full.endsWith(suffix)) {
        return new BoundedInputStream(tar, size);
      }
      long skip = (size + 511) / 512 * 512;
      tar.skipNBytes(skip);
    }
  }

  private static String cString(byte[] data, int offset, int length) {
    int end = offset;
    while (end < offset + length && data[end] != 0) {
      end++;
    }
    return new String(data, offset, end - offset, StandardCharsets.US_ASCII);
  }

  private static void copyLimited(InputStream in, OutputStream out, long maxBytes) throws IOException {
    byte[] buffer = new byte[65536];
    long total = 0;
    int read;
    while ((read = in.read(buffer)) >= 0) {
      total += read;
      if (total > maxBytes) {
        throw new IOException("Download exceeds " + maxBytes + " bytes");
      }
      out.write(buffer, 0, read);
    }
  }

  /**
   * Hides query parameters (license keys) in log output.
   *
   * @param url URL
   * @return URL without the query
   */
  public static String redact(String url) {
    int query = url.indexOf('?');
    return query < 0 ? url : url.substring(0, query) + "?…";
  }

  private static final class BoundedInputStream extends InputStream {
    private final InputStream in;
    private long remaining;

    BoundedInputStream(InputStream in, long remaining) {
      this.in = in;
      this.remaining = remaining;
    }

    @Override
    public int read() throws IOException {
      if (remaining <= 0) {
        return -1;
      }
      int b = in.read();
      if (b >= 0) {
        remaining--;
      }
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (remaining <= 0) {
        return -1;
      }
      int read = in.read(b, off, (int) Math.min(len, remaining));
      if (read > 0) {
        remaining -= read;
      }
      return read;
    }

    @Override
    public void close() throws IOException {
      in.close();
    }
  }
}
