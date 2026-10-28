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

package ru.moonlightproject.dev.thirdvelocity.api.geo;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * GeoIP and ASN lookup over local MaxMind-format ({@code .mmdb}) databases. By default the core
 * downloads the free DB-IP Lite databases; MaxMind GeoLite2 can be configured with a license key.
 */
public interface GeoIpService {

  /**
   * Looks up an address. Fast: reads memory-mapped databases and a small cache.
   *
   * @param address address
   * @return data, or {@link GeoInfo#UNKNOWN}
   */
  GeoInfo lookup(InetAddress address);

  /**
   * Downloads every configured database now, ignoring the update interval.
   *
   * @return status of each database after the attempt
   */
  CompletableFuture<List<DatabaseStatus>> update();

  /**
   * Returns the state of the configured databases.
   *
   * @return statuses
   */
  List<DatabaseStatus> status();
}
