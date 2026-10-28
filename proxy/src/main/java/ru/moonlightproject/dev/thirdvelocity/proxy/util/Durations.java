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

package ru.moonlightproject.dev.thirdvelocity.proxy.util;

import java.time.Duration;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses and formats short durations such as {@code 1d12h}, {@code 30m}, {@code 45s}. */
public final class Durations {

  private static final Pattern PART = Pattern.compile("(\\d+)\\s*(mo|[smhdwy])");

  private Durations() {
  }

  /**
   * Parses a duration. Plain numbers are seconds. Units: s, m, h, d, w, mo (30 days), y.
   *
   * @param text text
   * @return duration
   */
  public static Duration parse(String text) {
    String value = text.trim().toLowerCase(Locale.ROOT);
    if (value.matches("\\d+")) {
      return Duration.ofSeconds(Long.parseLong(value));
    }
    Matcher matcher = PART.matcher(value);
    Duration total = Duration.ZERO;
    int end = 0;
    while (matcher.find()) {
      if (matcher.start() != end && !value.substring(end, matcher.start()).isBlank()) {
        throw new IllegalArgumentException("Invalid duration: " + text);
      }
      long amount = Long.parseLong(matcher.group(1));
      total = total.plus(switch (matcher.group(2)) {
        case "s" -> Duration.ofSeconds(amount);
        case "m" -> Duration.ofMinutes(amount);
        case "h" -> Duration.ofHours(amount);
        case "d" -> Duration.ofDays(amount);
        case "w" -> Duration.ofDays(amount * 7);
        case "mo" -> Duration.ofDays(amount * 30);
        default -> Duration.ofDays(amount * 365);
      });
      end = matcher.end();
    }
    if (end == 0 || end != value.length()) {
      throw new IllegalArgumentException("Invalid duration: " + text);
    }
    return total;
  }

  /**
   * Reports whether text looks like a duration.
   *
   * @param text text
   * @return true if {@link #parse(String)} would succeed
   */
  public static boolean isDuration(String text) {
    try {
      parse(text);
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Formats a duration compactly, for example {@code 2d 3h}.
   *
   * @param duration duration
   * @return text
   */
  public static String format(Duration duration) {
    long seconds = Math.max(0, duration.getSeconds());
    long days = seconds / 86400;
    long hours = seconds % 86400 / 3600;
    long minutes = seconds % 3600 / 60;
    long secs = seconds % 60;
    StringBuilder out = new StringBuilder();
    if (days > 0) {
      out.append(days).append("д ");
    }
    if (hours > 0) {
      out.append(hours).append("ч ");
    }
    if (minutes > 0 && days == 0) {
      out.append(minutes).append("м ");
    }
    if (secs > 0 && days == 0 && hours == 0) {
      out.append(secs).append("с ");
    }
    return out.isEmpty() ? "0с" : out.toString().trim();
  }
}
