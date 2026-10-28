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

import java.util.List;

/**
 * Accounts linked to one player.
 *
 * @param subject player name the report was built for
 * @param addresses addresses the subject used, most recent first
 * @param links linked accounts, highest confidence first
 */
public record AltReport(String subject, List<String> addresses, List<AltLink> links) {

  /**
   * Returns the links at or above a confidence.
   *
   * @param minimum minimum confidence from 0 to 1
   * @return filtered links
   */
  public List<AltLink> atLeast(double minimum) {
    return links.stream().filter(link -> link.confidence() >= minimum).toList();
  }

  /**
   * Reports whether any linked account is banned.
   *
   * @return true if a linked account has an active ban
   */
  public boolean anyBanned() {
    return links.stream().anyMatch(link -> link.ban() != null);
  }
}
