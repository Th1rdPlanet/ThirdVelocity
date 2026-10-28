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

import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;

/**
 * What a ban applies to. Use the nested records to create targets and {@link #parse(String,
 * String)} to read them from commands or storage.
 */
public sealed interface BanTarget {

  /**
   * Stable lowercase kind stored in the database: {@code ip}, {@code name}, {@code uuid},
   * {@code asn} or {@code country}.
   *
   * @return kind
   */
  String kind();

  /**
   * Normalized value stored in the database.
   *
   * @return value
   */
  String value();

  /**
   * Parses a target from its kind and value.
   *
   * @param kind one of {@code ip}, {@code cidr}, {@code name}, {@code uuid}, {@code asn},
   *     {@code country}
   * @param value value in the format of that kind
   * @return parsed target
   * @throws IllegalArgumentException for unknown kinds or malformed values
   */
  static BanTarget parse(String kind, String value) {
    return switch (kind.toLowerCase(Locale.ROOT)) {
      case "ip", "cidr", "subnet" -> new Ip(IpRange.parse(value));
      case "name", "nick", "player" -> new Name(value);
      case "uuid" -> new Uuid(UUID.fromString(value.trim()));
      case "asn", "as" -> new Asn(Long.parseLong(value.trim().toUpperCase(Locale.ROOT).replaceFirst("^AS", "")));
      case "country", "geo" -> new Country(value);
      default -> throw new IllegalArgumentException("Unknown ban kind: " + kind);
    };
  }

  /**
   * An address or network.
   *
   * @param range banned range; a single address is a {@code /32} or {@code /128}
   */
  record Ip(IpRange range) implements BanTarget {
    @Override
    public String kind() {
      return "ip";
    }

    @Override
    public String value() {
      return range.toString();
    }
  }

  /**
   * A player name, compared case-insensitively.
   *
   * @param name player name
   */
  record Name(String name) implements BanTarget {
    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_.\\-]{1,32}");

    /**
     * Validates the name.
     *
     * @param name player name
     */
    public Name {
      name = name.trim();
      if (!VALID.matcher(name).matches()) {
        throw new IllegalArgumentException("Invalid player name: " + name);
      }
    }

    @Override
    public String kind() {
      return "name";
    }

    @Override
    public String value() {
      return name.toLowerCase(Locale.ROOT);
    }
  }

  /**
   * A profile UUID.
   *
   * @param uuid profile UUID
   */
  record Uuid(UUID uuid) implements BanTarget {
    @Override
    public String kind() {
      return "uuid";
    }

    @Override
    public String value() {
      return uuid.toString();
    }
  }

  /**
   * An autonomous system resolved through the ASN GeoIP database.
   *
   * @param asn AS number without the {@code AS} prefix
   */
  record Asn(long asn) implements BanTarget {
    /**
     * Validates the number.
     *
     * @param asn AS number
     */
    public Asn {
      if (asn <= 0 || asn > 4294967295L) {
        throw new IllegalArgumentException("Invalid AS number: " + asn);
      }
    }

    @Override
    public String kind() {
      return "asn";
    }

    @Override
    public String value() {
      return Long.toString(asn);
    }
  }

  /**
   * A country resolved through the country GeoIP database.
   *
   * @param code ISO 3166-1 alpha-2 code, for example {@code RU}
   */
  record Country(String code) implements BanTarget {
    /**
     * Validates and uppercases the code.
     *
     * @param code ISO code
     */
    public Country {
      code = code.trim().toUpperCase(Locale.ROOT);
      if (!code.matches("[A-Z]{2}")) {
        throw new IllegalArgumentException("Invalid ISO country code: " + code);
      }
    }

    @Override
    public String kind() {
      return "country";
    }

    @Override
    public String value() {
      return code;
    }
  }
}
