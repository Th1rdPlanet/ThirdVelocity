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

package ru.moonlightproject.dev.thirdvelocity.api.intel;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import ru.moonlightproject.dev.thirdvelocity.api.geo.DatabaseStatus;

/**
 * Downloaded and local IP lists. Each list assigns tags (for example {@code tor}, {@code vpn},
 * {@code hosting}, {@code blocklist}) to networks; the reputation rules give points per tag.
 */
public interface IpListService {

  /**
   * Returns the tags of every list containing the address. Fast.
   *
   * @param address address
   * @return tags, empty if the address is in no list
   */
  Set<String> tags(InetAddress address);

  /**
   * Returns the names of the lists containing the address. Fast.
   *
   * @param address address
   * @return list names
   */
  Set<String> lists(InetAddress address);

  /**
   * Downloads every list now.
   *
   * @return status of each list after the attempt
   */
  CompletableFuture<List<DatabaseStatus>> update();

  /**
   * Returns the state of the configured lists.
   *
   * @return statuses
   */
  List<DatabaseStatus> status();
}
