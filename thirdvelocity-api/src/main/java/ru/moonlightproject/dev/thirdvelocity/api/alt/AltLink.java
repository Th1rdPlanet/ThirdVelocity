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

package ru.moonlightproject.dev.thirdvelocity.api.alt;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.ban.Ban;

/**
 * An account linked to the subject of an {@link AltReport}.
 *
 * @param name account name as last seen
 * @param confidence combined confidence from 0 to 1
 * @param reasons link reasons
 * @param sharedAddresses addresses (or subnets) shared with the subject
 * @param depth 1 for a direct link, 2 and more for links through other accounts
 * @param lastSeen last time the account connected
 * @param ban active ban of the account, or {@code null}
 */
public record AltLink(
    String name,
    double confidence,
    Set<LinkReason> reasons,
    List<String> sharedAddresses,
    int depth,
    @Nullable Instant lastSeen,
    @Nullable Ban ban) {
}
