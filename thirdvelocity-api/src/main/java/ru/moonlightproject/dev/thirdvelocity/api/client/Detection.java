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

/**
 * A rule from {@code thirdvelocity/clients.yml} that matched a client.
 *
 * @param id rule id
 * @param kind rule kind: {@code loader}, {@code client}, {@code launcher}, {@code mod} or a custom
 *     value
 * @param label display name
 * @param action configured action: {@code none}, {@code flag} or {@code kick}
 */
public record Detection(String id, String kind, String label, String action) {
}
