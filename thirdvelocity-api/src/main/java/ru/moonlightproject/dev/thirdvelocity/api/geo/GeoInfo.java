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

import org.jspecify.annotations.Nullable;

/**
 * GeoIP data for one address. Any field may be missing when the corresponding database is
 * disabled, not downloaded yet or has no record.
 *
 * @param countryCode ISO 3166-1 alpha-2 code, for example {@code DE}
 * @param countryName English country name
 * @param continentCode continent code, for example {@code EU}
 * @param city English city name (only with a city database)
 * @param asn autonomous system number, or {@code -1}
 * @param asOrganization autonomous system organization
 */
public record GeoInfo(
    @Nullable String countryCode,
    @Nullable String countryName,
    @Nullable String continentCode,
    @Nullable String city,
    long asn,
    @Nullable String asOrganization) {

  /** Result for an address without any data. */
  public static final GeoInfo UNKNOWN = new GeoInfo(null, null, null, null, -1, null);

  /**
   * Reports whether nothing is known.
   *
   * @return true if every field is empty
   */
  public boolean isUnknown() {
    return countryCode == null && city == null && asn < 0 && asOrganization == null;
  }
}
