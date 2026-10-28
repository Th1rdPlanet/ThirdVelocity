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

package ru.moonlightproject.dev.thirdvelocity.api.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

/**
 * An IPv4 or IPv6 network in CIDR notation. The base address is always normalized to the network
 * address, so {@code 10.1.2.3/8} becomes {@code 10.0.0.0/8}. IPv4-mapped IPv6 addresses are
 * treated as IPv4.
 *
 * @param address network address
 * @param prefix prefix length (0-32 for IPv4, 0-128 for IPv6)
 */
public record IpRange(InetAddress address, int prefix) {

  /**
   * Creates a normalized range.
   *
   * @param address any address inside the network
   * @param prefix prefix length
   */
  public IpRange {
    Objects.requireNonNull(address, "address");
    byte[] raw = canonicalBytes(address);
    int bits = raw.length * 8;
    if (prefix < 0 || prefix > bits) {
      throw new IllegalArgumentException("Prefix " + prefix + " is out of range for " + address);
    }
    mask(raw, prefix);
    try {
      address = InetAddress.getByAddress(raw);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Creates a single-host range ({@code /32} or {@code /128}).
   *
   * @param address host address
   * @return host range
   */
  public static IpRange host(InetAddress address) {
    return new IpRange(address, canonicalBytes(address).length * 8);
  }

  /**
   * Parses {@code 1.2.3.4}, {@code 1.2.3.0/24}, {@code 2001:db8::/32} or {@code 2001:db8::1}.
   * Host names are rejected; no DNS lookup is performed.
   *
   * @param text address or CIDR
   * @return parsed range
   * @throws IllegalArgumentException if the text is not a literal address or CIDR
   */
  public static IpRange parse(String text) {
    String value = text.trim();
    int slash = value.indexOf('/');
    String host = slash < 0 ? value : value.substring(0, slash);
    InetAddress address = parseLiteral(host);
    int bits = canonicalBytes(address).length * 8;
    int prefix = bits;
    if (slash >= 0) {
      try {
        prefix = Integer.parseInt(value.substring(slash + 1));
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid prefix in " + text);
      }
    }
    return new IpRange(address, prefix);
  }

  /**
   * Parses a literal IPv4 or IPv6 address without DNS.
   *
   * @param text address literal
   * @return address
   * @throws IllegalArgumentException if the text is not a literal address
   */
  public static InetAddress parseLiteral(String text) {
    String host = text.trim();
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    if (host.isEmpty() || !(host.indexOf(':') >= 0 || host.matches("[0-9.]+"))) {
      throw new IllegalArgumentException("Not an IP literal: " + text);
    }
    if (host.indexOf(':') < 0 && !host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
      throw new IllegalArgumentException("Not an IPv4 literal: " + text);
    }
    if (host.indexOf(':') >= 0 && !host.matches("[0-9A-Fa-f:.]+")) {
      throw new IllegalArgumentException("Not an IPv6 literal: " + text);
    }
    try {
      return InetAddress.getByName(host);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Not an IP literal: " + text, e);
    }
  }

  /**
   * Returns the address bytes, unwrapping IPv4-mapped IPv6 addresses to four bytes.
   *
   * @param address address
   * @return 4 or 16 bytes
   */
  public static byte[] canonicalBytes(InetAddress address) {
    byte[] raw = address.getAddress();
    if (raw.length == 16) {
      boolean mapped = true;
      for (int i = 0; i < 10; i++) {
        if (raw[i] != 0) {
          mapped = false;
          break;
        }
      }
      if (mapped && raw[10] == (byte) 0xff && raw[11] == (byte) 0xff) {
        return new byte[] {raw[12], raw[13], raw[14], raw[15]};
      }
    }
    return raw;
  }

  /**
   * Reports whether this is an IPv4 range.
   *
   * @return true for IPv4
   */
  public boolean isIpv4() {
    return address.getAddress().length == 4;
  }

  /**
   * Reports whether the address is inside this range.
   *
   * @param candidate address to test
   * @return true if the address belongs to the network
   */
  public boolean contains(InetAddress candidate) {
    byte[] raw = canonicalBytes(candidate);
    byte[] base = address.getAddress();
    if (raw.length != base.length) {
      return false;
    }
    mask(raw, prefix);
    return java.util.Arrays.equals(raw, base);
  }

  private static void mask(byte[] raw, int prefix) {
    for (int i = 0; i < raw.length; i++) {
      int remaining = prefix - i * 8;
      if (remaining >= 8) {
        continue;
      }
      if (remaining <= 0) {
        raw[i] = 0;
      } else {
        raw[i] = (byte) (raw[i] & (0xff << (8 - remaining)));
      }
    }
  }

  @Override
  public String toString() {
    return address.getHostAddress() + "/" + prefix;
  }
}
