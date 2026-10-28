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

package ru.moonlightproject.dev.thirdvelocity.api.event;

import java.net.InetAddress;

/**
 * Fired after the core refused a connection. Informational: the connection is already closed.
 * Fired at most once per address per second to keep floods cheap.
 *
 * @param address remote address
 * @param stage {@code accept}, {@code handshake} or {@code login}
 * @param reason reason id: {@code ban}, {@code reputation}, {@code rate}, {@code concurrency},
 *     {@code attack}, {@code hostname}, {@code name}, {@code proxy-protocol}, {@code client}
 * @param detail human-readable detail
 */
public record ConnectionBlockedEvent(InetAddress address, String stage, String reason, String detail) {
}
