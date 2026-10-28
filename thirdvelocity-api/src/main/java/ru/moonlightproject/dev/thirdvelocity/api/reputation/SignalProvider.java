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
import java.util.List;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;

/**
 * Plugin-supplied scoring rule. Called for every assessment, often on a Netty event loop, so it
 * must be fast, thread-safe and must not block.
 */
@FunctionalInterface
public interface SignalProvider {

  /**
   * Returns extra signals for an address.
   *
   * @param address scored address
   * @param geo GeoIP data
   * @return signals, possibly empty
   */
  List<Signal> signals(InetAddress address, GeoInfo geo);
}
