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

package ru.moonlightproject.dev.thirdvelocity.api.protection;

import java.net.InetAddress;
import java.util.Set;

/**
 * Attack detection and traffic counters.
 */
public interface ProtectionService {

  /**
   * Returns the current attack level. Fast.
   *
   * @return level
   */
  AttackLevel level();

  /**
   * Returns the last full second of traffic counters. Fast.
   *
   * @return counters
   */
  TrafficSnapshot traffic();

  /**
   * Returns cumulative counters since start. Fast.
   *
   * @return counters
   * @since 1.1.0
   */
  ProtectionTotals totals();

  /**
   * Reports the outcome of an authentication step (password, CAPTCHA, 2FA) from an authentication
   * plugin. The core is the single owner of the network attack level: the failure ratio over the
   * attack window raises the level by {@code protection.yml → attack.signals}. Fast.
   *
   * @param failed whether the step failed
   * @since 1.2.0
   */
  void reportAuthentication(boolean failed);

  /**
   * Reports how many logins an authentication plugin currently has in progress (connected but
   * not authenticated). Many unfinished logins also raise the attack level. Fast; call it about
   * once per second.
   *
   * @param source plugin id, so several plugins can report independently
   * @param pending logins in progress
   * @since 1.2.0
   */
  void reportPendingLogins(String source, int pending);

  /**
   * Combined suspicion check used by authentication plugins: IP verdict, name/IP behaviour and
   * client detections. Fast.
   *
   * @param name player name
   * @param address player address
   * @return true if the player should get extra checks such as CAPTCHA
   */
  boolean suspicious(String name, InetAddress address);

  /**
   * Returns addresses that connected at least once before (authenticated or not) within the
   * retention window. Fast membership test.
   *
   * @param address address
   * @return true if seen before
   */
  boolean known(InetAddress address);

  /**
   * Returns the addresses currently held by temporary rate-limit blocks. Fast.
   *
   * @return blocked addresses
   */
  Set<String> temporaryBlocks();
}
