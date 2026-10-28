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

package ru.moonlightproject.dev.thirdvelocity.api;

import ru.moonlightproject.dev.thirdvelocity.api.alt.AltService;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanService;
import ru.moonlightproject.dev.thirdvelocity.api.client.ClientService;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoIpService;
import ru.moonlightproject.dev.thirdvelocity.api.intel.IpListService;
import ru.moonlightproject.dev.thirdvelocity.api.protection.ProtectionService;
import ru.moonlightproject.dev.thirdvelocity.api.reputation.ReputationService;

/**
 * Services of the ThirdVelocity core.
 *
 * <p>Methods documented as <em>fast</em> read only memory and may be called on Netty event loops.
 * Methods returning {@link java.util.concurrent.CompletableFuture} touch the database or network
 * and complete on a ThirdVelocity worker thread.</p>
 *
 * <p>ThirdVelocity also fires the events from {@code ru.moonlightproject.dev.thirdvelocity.api.event}
 * on the Velocity event bus; subscribe to them with {@code @Subscribe} as to any other event.</p>
 */
public interface ThirdVelocityApi {

  /**
   * Returns the ThirdVelocity version.
   *
   * @return version string, for example {@code 1.0.0}
   */
  String version();

  /**
   * Returns the ban storage and matcher.
   *
   * @return ban service
   */
  BanService bans();

  /**
   * Returns GeoIP and ASN lookup.
   *
   * @return GeoIP service
   */
  GeoIpService geoIp();

  /**
   * Returns the downloaded IP lists (Tor, VPN, hosting, blocklists).
   *
   * @return IP list service
   */
  IpListService ipLists();

  /**
   * Returns IP scoring.
   *
   * @return reputation service
   */
  ReputationService reputation();

  /**
   * Returns account and IP link analysis (alts, shared IPs).
   *
   * @return alt service
   */
  AltService alts();

  /**
   * Returns client, mod and launcher detection.
   *
   * @return client service
   */
  ClientService clients();

  /**
   * Returns attack level and traffic counters.
   *
   * @return protection service
   */
  ProtectionService protection();
}
