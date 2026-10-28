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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;

/** Address helpers shared by the indexes. */
public final class IpKeys {

  private IpKeys() {
  }

  /**
   * Returns the canonical address (IPv4-mapped IPv6 unwrapped).
   *
   * @param address address
   * @return canonical address
   */
  public static InetAddress canonical(InetAddress address) {
    byte[] raw = IpRange.canonicalBytes(address);
    if (raw.length == address.getAddress().length) {
      return address;
    }
    try {
      return InetAddress.getByAddress(raw);
    } catch (UnknownHostException e) {
      return address;
    }
  }

  /**
   * Extracts the canonical address of a socket address.
   *
   * @param socket socket address
   * @return address or {@code null} for non-IP sockets (Unix domain)
   */
  public static @Nullable InetAddress of(@Nullable SocketAddress socket) {
    if (socket instanceof InetSocketAddress inet && inet.getAddress() != null) {
      return canonical(inet.getAddress());
    }
    return null;
  }

  /**
   * Returns the canonical text form used in storage.
   *
   * @param address address
   * @return text
   */
  public static String text(InetAddress address) {
    return canonical(address).getHostAddress();
  }

  /**
   * Returns the subnet an address belongs to, as CIDR text.
   *
   * @param address address
   * @param v4Prefix IPv4 prefix length
   * @param v6Prefix IPv6 prefix length
   * @return CIDR text
   */
  public static String subnet(InetAddress address, int v4Prefix, int v6Prefix) {
    InetAddress canonical = canonical(address);
    int prefix = canonical.getAddress().length == 4 ? v4Prefix : v6Prefix;
    return new IpRange(canonical, prefix).toString();
  }

  /**
   * Packs an IPv4 address into the low 32 bits of a long.
   *
   * @param raw four bytes
   * @return value
   */
  public static long v4(byte[] raw) {
    return ((raw[0] & 0xffL) << 24) | ((raw[1] & 0xffL) << 16) | ((raw[2] & 0xffL) << 8) | (raw[3] & 0xffL);
  }

  /**
   * Returns the high 64 bits of an IPv6 address.
   *
   * @param raw sixteen bytes
   * @return value
   */
  public static long hi(byte[] raw) {
    long value = 0;
    for (int i = 0; i < 8; i++) {
      value = (value << 8) | (raw[i] & 0xffL);
    }
    return value;
  }

  /**
   * Returns the low 64 bits of an IPv6 address.
   *
   * @param raw sixteen bytes
   * @return value
   */
  public static long lo(byte[] raw) {
    long value = 0;
    for (int i = 8; i < 16; i++) {
      value = (value << 8) | (raw[i] & 0xffL);
    }
    return value;
  }

  /**
   * Returns a 64-bit key for set membership: IPv4 is exact, IPv6 is a strong hash.
   *
   * @param address address
   * @return key
   */
  public static long key(InetAddress address) {
    byte[] raw = IpRange.canonicalBytes(address);
    if (raw.length == 4) {
      return v4(raw) | (1L << 40);
    }
    long h = hi(raw) * 0x9E3779B97F4A7C15L;
    h ^= Long.rotateLeft(lo(raw) * 0xC2B2AE3D27D4EB4FL, 31);
    h ^= h >>> 29;
    return h | (1L << 62);
  }
}
