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

/** What the core recommends doing with a connection. */
public enum Verdict {
  /** Let the connection in normally. */
  ALLOW,
  /** Let it in but mark it suspicious; authentication plugins should require CAPTCHA. */
  FLAG,
  /** Refuse the connection. The core does so itself when {@code reputation.enforce-deny} is on. */
  DENY
}
