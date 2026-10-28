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

/**
 * Counters for the last full second. Payloads are never inspected.
 *
 * @param connections accepted TCP connections
 * @param blocked connections closed by the early filter
 * @param handshakes login handshakes
 * @param pings status requests
 * @param inboundBytes bytes received from clients
 * @param outboundBytes bytes sent to clients
 * @param outboundPackets frames sent to clients
 * @param openConnections currently open client connections
 */
public record TrafficSnapshot(
    long connections,
    long blocked,
    long handshakes,
    long pings,
    long inboundBytes,
    long outboundBytes,
    long outboundPackets,
    long openConnections) {
}
