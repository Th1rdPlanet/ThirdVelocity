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

package ru.moonlightproject.dev.thirdvelocity.proxy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.geo.DatabaseStatus;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;

/** Prometheus text endpoint on {@code /metrics}. Labels come from closed sets (reasons, lists). */
final class MetricsServer {

  private static final Logger LOGGER = LogManager.getLogger("ThirdVelocity");

  private final ThirdVelocityCore core;
  private @Nullable HttpServer server;

  MetricsServer(ThirdVelocityCore core) {
    this.core = core;
  }

  void start(ConfigNode config) throws IOException {
    if (!config.bool("enabled", false)) {
      return;
    }
    String bind = config.string("bind", "127.0.0.1:9465");
    int colon = bind.lastIndexOf(':');
    if (colon <= 0) {
      throw new ConfigNode.ConfigException("config.yml: metrics.bind must be host:port");
    }
    String host = bind.substring(0, colon).replace("[", "").replace("]", "");
    int port = Integer.parseInt(bind.substring(colon + 1));
    HttpServer http = HttpServer.create(new InetSocketAddress(host, port), 16);
    http.setExecutor(Executors.newSingleThreadExecutor(runnable -> {
      Thread thread = new Thread(runnable, "ThirdVelocity-Metrics");
      thread.setDaemon(true);
      return thread;
    }));
    http.createContext("/metrics", exchange -> {
      byte[] body = render().getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    http.start();
    server = http;
    LOGGER.info("Prometheus metrics on http://{}/metrics", bind);
  }

  void stop() {
    HttpServer http = server;
    if (http != null) {
      http.stop(0);
    }
  }

  private static String label(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
  }

  String render() {
    StringBuilder out = new StringBuilder(4096);
    out.append("# TYPE thirdvelocity_build_info gauge\n")
        .append("thirdvelocity_build_info{version=\"").append(ThirdVelocityCore.VERSION).append("\"} 1\n");
    for (Map.Entry<String, Long> total : core.protectionManager().totals().entrySet()) {
      String name = "thirdvelocity_" + total.getKey() + "_total";
      out.append("# TYPE ").append(name).append(" counter\n").append(name).append(' ').append(total.getValue()).append('\n');
    }
    out.append("# TYPE thirdvelocity_refused_total counter\n");
    for (Map.Entry<String, Long> reason : core.filter().blockedTotals().entrySet()) {
      out.append("thirdvelocity_refused_total{reason=\"").append(label(reason.getKey())).append("\"} ")
          .append(reason.getValue()).append('\n');
    }
    gauge(out, "thirdvelocity_attack_level", core.protectionManager().level().ordinal());
    gauge(out, "thirdvelocity_open_connections", core.protectionManager().traffic().openConnections());
    gauge(out, "thirdvelocity_players_online", core.server().getPlayerCount());
    gauge(out, "thirdvelocity_bans_active", core.bans().active().size());
    gauge(out, "thirdvelocity_temporary_blocks_active", core.protectionManager().activeBlocks());
    gauge(out, "thirdvelocity_known_addresses", core.protectionManager().knownAddresses().size());
    out.append("# TYPE thirdvelocity_geoip_loaded gauge\n");
    for (DatabaseStatus status : core.geoIp().status()) {
      out.append("thirdvelocity_geoip_loaded{database=\"").append(label(status.name())).append("\"} ")
          .append(status.loaded() ? 1 : 0).append('\n');
    }
    out.append("# TYPE thirdvelocity_ip_list_networks gauge\n");
    for (DatabaseStatus status : core.ipLists().status()) {
      out.append("thirdvelocity_ip_list_networks{list=\"").append(label(status.name())).append("\"} ")
          .append(Math.max(0, status.entries())).append('\n');
    }
    return out.toString();
  }

  private static void gauge(StringBuilder out, String name, long value) {
    out.append("# TYPE ").append(name).append(" gauge\n").append(name).append(' ').append(value).append('\n');
  }
}
