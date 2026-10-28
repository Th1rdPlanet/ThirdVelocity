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

package ru.moonlightproject.dev.thirdvelocity.api.client;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * What the proxy knows about a connected client. Everything here is sent by the client and can
 * be forged by a modified client; use it for statistics and soft signals, not as proof.
 *
 * @param playerId player UUID
 * @param name player name
 * @param protocol protocol version number
 * @param version version name, for example {@code 1.21.8}
 * @param rawHost handshake host string including loader markers
 * @param loginUuid UUID the client sent in its login packet (1.20.2+), or {@code null}
 * @param offlineUuidMatches whether that UUID equals the standard offline UUID of the name;
 *     {@code null} when not applicable
 * @param brand client brand from {@code minecraft:brand}, or {@code null}
 * @param loader detected loader
 * @param channels plugin channels registered by the client
 * @param mods mod ids derived from channel namespaces and loader data
 * @param locale client locale, or {@code null} before settings arrive
 * @param viewDistance view distance, or {@code -1}
 * @param skinParts displayed skin parts bit mask, or {@code -1}
 * @param mainHandRight whether the main hand is right
 * @param detections matched rules (clients, launchers, mods)
 * @param fingerprint stable hash of the fields above, used for alt detection
 */
public record ClientInfo(
    UUID playerId,
    String name,
    int protocol,
    String version,
    String rawHost,
    @Nullable UUID loginUuid,
    @Nullable Boolean offlineUuidMatches,
    @Nullable String brand,
    ClientLoader loader,
    Set<String> channels,
    Set<String> mods,
    @Nullable String locale,
    int viewDistance,
    int skinParts,
    boolean mainHandRight,
    List<Detection> detections,
    String fingerprint) {

  /**
   * Returns the label of the first detection of the given kind.
   *
   * @param kind detection kind, for example {@code launcher}
   * @return label or {@code null}
   */
  public @Nullable String detected(String kind) {
    for (Detection detection : detections) {
      if (detection.kind().equals(kind)) {
        return detection.label();
      }
    }
    return null;
  }
}
