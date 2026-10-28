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
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import org.jspecify.annotations.Nullable;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;

/**
 * Immutable longest-prefix index from networks to values. Lookup cost is one hash probe per
 * distinct prefix length present, so it stays fast with any number of entries.
 *
 * @param <T> value type
 */
public final class PrefixIndex<T> {

  private record V6(long hi, long lo) {
  }

  private final Map<Integer, Map<Long, T>> v4 = new HashMap<>();
  private final Map<Integer, Map<V6, T>> v6 = new HashMap<>();
  private int[] v4Prefixes = new int[0];
  private int[] v6Prefixes = new int[0];

  /** Builder collecting entries; later entries for the same network win. */
  public static final class Builder<T> {
    private final PrefixIndex<T> index = new PrefixIndex<>();
    private final TreeSet<Integer> p4 = new TreeSet<>();
    private final TreeSet<Integer> p6 = new TreeSet<>();

    /**
     * Adds a network.
     *
     * @param range network
     * @param value value
     * @return this builder
     */
    public Builder<T> put(IpRange range, T value) {
      byte[] raw = range.address().getAddress();
      if (raw.length == 4) {
        index.v4.computeIfAbsent(range.prefix(), k -> new HashMap<>()).put(IpKeys.v4(raw), value);
        p4.add(range.prefix());
      } else {
        index.v6.computeIfAbsent(range.prefix(), k -> new HashMap<>())
            .put(new V6(IpKeys.hi(raw), IpKeys.lo(raw)), value);
        p6.add(range.prefix());
      }
      return this;
    }

    /**
     * Finishes the index.
     *
     * @return index
     */
    public PrefixIndex<T> build() {
      index.v4Prefixes = p4.descendingSet().stream().mapToInt(Integer::intValue).toArray();
      index.v6Prefixes = p6.descendingSet().stream().mapToInt(Integer::intValue).toArray();
      return index;
    }
  }

  /**
   * Creates a builder.
   *
   * @param <T> value type
   * @return builder
   */
  public static <T> Builder<T> builder() {
    return new Builder<>();
  }

  /**
   * Finds the value of the most specific network containing the address.
   *
   * @param address address
   * @return value or {@code null}
   */
  public @Nullable T longestMatch(InetAddress address) {
    byte[] raw = IpRange.canonicalBytes(address);
    if (raw.length == 4) {
      long value = IpKeys.v4(raw);
      for (int prefix : v4Prefixes) {
        long masked = prefix == 0 ? 0 : value & (0xffffffffL << (32 - prefix)) & 0xffffffffL;
        T hit = v4.get(prefix).get(masked);
        if (hit != null) {
          return hit;
        }
      }
      return null;
    }
    long hi = IpKeys.hi(raw);
    long lo = IpKeys.lo(raw);
    for (int prefix : v6Prefixes) {
      long mh;
      long ml;
      if (prefix == 0) {
        mh = 0;
        ml = 0;
      } else if (prefix <= 64) {
        mh = hi & (-1L << (64 - prefix));
        ml = 0;
      } else {
        mh = hi;
        ml = prefix == 128 ? lo : lo & (-1L << (128 - prefix));
      }
      T hit = v6.get(prefix).get(new V6(mh, ml));
      if (hit != null) {
        return hit;
      }
    }
    return null;
  }

  /**
   * Reports whether the index is empty.
   *
   * @return true when empty
   */
  public boolean isEmpty() {
    return v4Prefixes.length == 0 && v6Prefixes.length == 0;
  }
}
