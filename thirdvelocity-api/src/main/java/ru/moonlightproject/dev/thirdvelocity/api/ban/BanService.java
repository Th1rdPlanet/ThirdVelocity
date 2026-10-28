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

package ru.moonlightproject.dev.thirdvelocity.api.ban;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.jspecify.annotations.Nullable;

/**
 * Ban storage and matching.
 *
 * <p>The core keeps all active bans in memory. Matching methods are fast and are what the proxy
 * itself uses to drop banned connections right after {@code accept()}. Whether the proxy enforces
 * bans by itself is controlled by {@code bans.enforce}; with enforcement off the storage and API
 * still work, so a separate punishment plugin can use them.</p>
 *
 * <p>With a shared MySQL/MariaDB/PostgreSQL database every proxy picks up bans created by the
 * others within {@code storage.sync-seconds}.</p>
 */
public interface BanService {

  /**
   * Reports whether the proxy enforces bans by itself.
   *
   * @return value of {@code bans.enforce}
   */
  boolean enforcing();

  /**
   * Stores a ban and applies it immediately. Online players matching the target are disconnected
   * when {@code bans.kick-online} is enabled.
   *
   * @param request ban parameters
   * @return the stored ban
   */
  CompletableFuture<Ban> ban(BanRequest request);

  /**
   * Lifts a ban by id.
   *
   * @param id ban id
   * @param actor who lifts the ban
   * @return the revoked ban, or empty if no active ban had this id
   */
  CompletableFuture<Optional<Ban>> revoke(long id, String actor);

  /**
   * Lifts every active ban with exactly this target.
   *
   * @param target ban target
   * @param actor who lifts the bans
   * @return revoked bans
   */
  CompletableFuture<List<Ban>> revoke(BanTarget target, String actor);

  /**
   * Finds the most specific active ban covering the address: exact IP, then the narrowest
   * network, then ASN and country. Fast.
   *
   * @param address connecting address
   * @return matching ban
   */
  Optional<Ban> matchAddress(InetAddress address);

  /**
   * Finds an active ban for a player name or profile UUID. Fast.
   *
   * @param name player name, compared case-insensitively
   * @param uuid profile UUID or {@code null}
   * @return matching ban
   */
  Optional<Ban> matchPlayer(String name, @Nullable UUID uuid);

  /**
   * Returns every active ban. Fast.
   *
   * @return active bans, newest first
   */
  List<Ban> active();

  /**
   * Returns active bans whose target is exactly this one. Fast.
   *
   * @param target target
   * @return matching bans
   */
  List<Ban> active(BanTarget target);

  /**
   * Loads the full ban history, including expired and revoked bans, from the database.
   *
   * @param offset rows to skip
   * @param limit maximum rows, at most 1000
   * @return bans, newest first
   */
  CompletableFuture<List<Ban>> history(int offset, int limit);

  /**
   * Loads a ban by id, including revoked and expired ones.
   *
   * @param id ban id
   * @return ban
   */
  CompletableFuture<Optional<Ban>> byId(long id);
}
