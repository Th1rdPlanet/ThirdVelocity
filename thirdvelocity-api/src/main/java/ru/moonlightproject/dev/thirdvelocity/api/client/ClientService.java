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

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

/**
 * Client, mod and launcher detection for connected players.
 */
public interface ClientService {

  /**
   * Returns what is known about an online player. Fast.
   *
   * @param playerId player UUID
   * @return client data, empty if the player is offline
   */
  Optional<ClientInfo> get(UUID playerId);

  /**
   * Returns data of every online player. Fast.
   *
   * @return client data
   */
  Collection<ClientInfo> online();
}
