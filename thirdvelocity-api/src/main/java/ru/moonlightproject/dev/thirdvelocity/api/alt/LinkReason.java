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

/** Why two accounts are considered linked. */
public enum LinkReason {
  /** Both accounts used the same IP address. */
  SAME_IP,
  /** Both accounts used addresses from the same subnet and autonomous system. */
  SAME_SUBNET,
  /** Both accounts sent the same client fingerprint (brand, mods, settings). */
  SAME_FINGERPRINT,
  /** Linked through another account (depth above one). */
  TRANSITIVE
}
