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

package ru.moonlightproject.dev.thirdvelocity.proxy.protection;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.protection.AttackLevel;

/**
 * Caches the serialized server-list response while the attack level is high, so ping floods do
 * not run {@code ProxyPingEvent} and JSON serialization for every request. Keyed by protocol
 * version (the response echoes it) and virtual host.
 */
public final class StatusCache {

  private record Entry(String json, long expiresAt) {
  }

  private final Map<String, Entry> entries = new ConcurrentHashMap<>();
  private volatile boolean enabled = true;
  private volatile AttackLevel minimumLevel = AttackLevel.LOW;
  private volatile long ttlMillis = 1500;

  void configure(boolean enabled, AttackLevel minimumLevel, long ttlMillis) {
    this.enabled = enabled;
    this.minimumLevel = minimumLevel;
    this.ttlMillis = ttlMillis;
    entries.clear();
  }

  /**
   * Reports whether caching is active at the given level.
   *
   * @param level current attack level
   * @return true when responses should be cached
   */
  public boolean active(AttackLevel level) {
    return enabled && level.compareTo(minimumLevel) >= 0;
  }

  private static String key(int protocol, String host) {
    return protocol + "|" + host;
  }

  /**
   * Returns a fresh cached response.
   *
   * @param protocol client protocol
   * @param host virtual host
   * @return JSON or {@code null}
   */
  public @Nullable String get(int protocol, String host) {
    Entry entry = entries.get(key(protocol, host));
    if (entry == null || entry.expiresAt() < System.currentTimeMillis()) {
      return null;
    }
    return entry.json();
  }

  /**
   * Stores a response.
   *
   * @param protocol client protocol
   * @param host virtual host
   * @param json serialized response
   */
  public void put(int protocol, String host, String json) {
    if (entries.size() > 4096) {
      entries.clear();
    }
    entries.put(key(protocol, host), new Entry(json, System.currentTimeMillis() + ttlMillis));
  }
}
