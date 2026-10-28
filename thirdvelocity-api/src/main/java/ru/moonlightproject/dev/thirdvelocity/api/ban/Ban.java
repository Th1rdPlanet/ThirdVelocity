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

package ru.moonlightproject.dev.thirdvelocity.api.ban;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A stored ban.
 *
 * @param id database identifier
 * @param target what is banned
 * @param reason reason shown to the player and staff, may be empty
 * @param actor who created the ban (player name, {@code CONSOLE} or a plugin id)
 * @param createdAt creation time
 * @param expiresAt expiry time, or {@code null} for a permanent ban
 * @param revokedAt time the ban was lifted, or {@code null} while it is in force
 * @param revokedBy who lifted the ban, or {@code null}
 */
public record Ban(
    long id,
    BanTarget target,
    String reason,
    String actor,
    Instant createdAt,
    @Nullable Instant expiresAt,
    @Nullable Instant revokedAt,
    @Nullable String revokedBy) {

  /**
   * Validates the ban.
   */
  public Ban {
    Objects.requireNonNull(target, "target");
    Objects.requireNonNull(createdAt, "createdAt");
    reason = reason == null ? "" : reason;
    actor = actor == null ? "" : actor;
  }

  /**
   * Reports whether the ban currently applies.
   *
   * @param now current time
   * @return true if not revoked and not expired
   */
  public boolean activeAt(Instant now) {
    return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
  }

  /**
   * Reports whether the ban is permanent.
   *
   * @return true when there is no expiry
   */
  public boolean permanent() {
    return expiresAt == null;
  }
}
