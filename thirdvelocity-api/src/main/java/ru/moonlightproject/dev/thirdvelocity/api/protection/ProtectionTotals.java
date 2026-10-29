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

import java.util.Map;

/**
 * Cumulative counters since the proxy started, for exporters such as Prometheus. Counters only
 * grow; compute rates on the exporter side.
 *
 * @param connections accepted TCP connections
 * @param refused connections refused by the core
 * @param refusedByReason refusals per reason id ({@code ban}, {@code rate}, {@code reputation},
 *     {@code attack}, {@code concurrency}, {@code hostname}, {@code status-rate}, ...)
 * @param handshakes login handshakes
 * @param pings status requests
 * @param inboundBytes bytes received from clients
 * @param outboundBytes bytes sent to clients
 * @param outboundPackets frames sent to clients
 * @param temporaryBlocks temporary blocks created
 * @param activeTemporaryBlocks temporary blocks currently in force
 * @param knownAddresses addresses seen before (retention window)
 */
public record ProtectionTotals(
    long connections,
    long refused,
    Map<String, Long> refusedByReason,
    long handshakes,
    long pings,
    long inboundBytes,
    long outboundBytes,
    long outboundPackets,
    long temporaryBlocks,
    long activeTemporaryBlocks,
    long knownAddresses) {
}
