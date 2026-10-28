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

import java.time.Duration;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Parameters of a new ban.
 *
 * @param target what to ban
 * @param reason reason, may be empty
 * @param actor who bans; plugins should use their id
 * @param duration ban length, or {@code null} for a permanent ban
 */
public record BanRequest(BanTarget target, String reason, String actor, @Nullable Duration duration) {

  /**
   * Validates the request.
   */
  public BanRequest {
    Objects.requireNonNull(target, "target");
    reason = reason == null ? "" : reason;
    actor = actor == null || actor.isBlank() ? "API" : actor;
    if (duration != null && (duration.isNegative() || duration.isZero())) {
      throw new IllegalArgumentException("Ban duration must be positive");
    }
  }

  /**
   * Creates a permanent ban request.
   *
   * @param target what to ban
   * @param reason reason
   * @param actor who bans
   * @return request
   */
  public static BanRequest permanent(BanTarget target, String reason, String actor) {
    return new BanRequest(target, reason, actor, null);
  }
}
