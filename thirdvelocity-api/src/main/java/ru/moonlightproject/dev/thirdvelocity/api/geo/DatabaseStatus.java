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

import java.time.Instant;
import org.jspecify.annotations.Nullable;

/**
 * State of one downloadable data source (GeoIP database or IP list).
 *
 * @param name configured name, for example {@code country} or {@code tor}
 * @param loaded whether data is loaded and used for lookups
 * @param entries number of records or networks, {@code -1} if unknown
 * @param buildTime build time reported by the source, or the download time
 * @param lastAttempt last update attempt
 * @param lastError message of the last failed update, or {@code null}
 */
public record DatabaseStatus(
    String name,
    boolean loaded,
    long entries,
    @Nullable Instant buildTime,
    @Nullable Instant lastAttempt,
    @Nullable String lastError) {
}
