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

package ru.moonlightproject.dev.thirdvelocity.api.reputation;

import java.net.InetAddress;
import java.util.concurrent.CompletableFuture;

/**
 * IP scoring from GeoIP, IP lists, connection behaviour, reported events, bans of linked
 * accounts and plugin providers. Every weight and threshold is configured in
 * {@code thirdvelocity/reputation.yml}.
 */
public interface ReputationService {

  /**
   * Scores an address from in-memory data. Fast; results are cached for a few seconds.
   *
   * @param address address
   * @return assessment
   */
  IpAssessment assess(InetAddress address);

  /**
   * Full scan: {@link #assess(InetAddress)} plus database history (accounts seen on the IP and
   * whether any of them is banned).
   *
   * @param address address
   * @return assessment
   */
  CompletableFuture<IpAssessment> scan(InetAddress address);

  /**
   * Records a behavioural event for an address. The points of the event are taken from
   * {@code events.<name>} in the config (or {@code events.default}) and decay over time.
   * Typical events: {@code auth.failed}, {@code captcha.failed}, {@code auth.success}.
   *
   * @param address address
   * @param event event name
   */
  void report(InetAddress address, String event);

  /**
   * Registers a plugin scoring rule.
   *
   * @param id unique provider id, used as signal id prefix
   * @param provider provider
   */
  void registerProvider(String id, SignalProvider provider);

  /**
   * Removes a plugin scoring rule.
   *
   * @param id provider id
   */
  void unregisterProvider(String id);
}
