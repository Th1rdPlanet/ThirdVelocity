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
import java.util.Set;
import ru.moonlightproject.dev.thirdvelocity.api.geo.GeoInfo;

/**
 * Result of scoring an IP address.
 *
 * @param address scored address
 * @param score sum of signal points
 * @param verdict verdict from the configured thresholds
 * @param signals contributions, highest first
 * @param geo GeoIP data used for scoring
 * @param tags IP list tags
 */
public record IpAssessment(
    InetAddress address,
    int score,
    Verdict verdict,
    List<Signal> signals,
    GeoInfo geo,
    Set<String> tags) {

  /**
   * Reports whether the verdict is {@link Verdict#FLAG} or {@link Verdict#DENY}.
   *
   * @return true when suspicious
   */
  public boolean suspicious() {
    return verdict != Verdict.ALLOW;
  }
}
