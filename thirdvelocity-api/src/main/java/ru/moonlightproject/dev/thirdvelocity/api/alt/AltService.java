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

package ru.moonlightproject.dev.thirdvelocity.api.alt;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Account/address graph used to find alts (twinks) and connected addresses.
 *
 * <p>The core records every successful proxy login. Authentication plugins should additionally
 * call {@link #recordAuthenticated(String, InetAddress)} after a password/2FA login: confirmed
 * logins weigh more than bare connection attempts.</p>
 */
public interface AltService {

  /**
   * Builds the alt report of a player.
   *
   * @param name player name, case-insensitive
   * @return report; empty links if nothing is linked
   */
  CompletableFuture<AltReport> alts(String name);

  /**
   * Lists accounts and related addresses for an address.
   *
   * @param address address
   * @return report
   */
  CompletableFuture<AddressReport> address(InetAddress address);

  /**
   * Returns the address history of a player.
   *
   * @param name player name
   * @return observations, most recent first
   */
  CompletableFuture<List<Observation>> history(String name);

  /**
   * Marks a login as confirmed by an authentication plugin.
   *
   * @param name player name
   * @param address player address
   */
  void recordAuthenticated(String name, InetAddress address);
}
