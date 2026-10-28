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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;

/**
 * Immutable set of networks stored as merged sorted intervals; membership is a binary search.
 * Suitable for lists with hundreds of thousands of networks.
 */
public final class IntervalSet {

  private final long[] v4Start;
  private final long[] v4End;
  private final long[] v6StartHi;
  private final long[] v6StartLo;
  private final long[] v6EndHi;
  private final long[] v6EndLo;
  private final int networks;

  private IntervalSet(long[] v4Start, long[] v4End, long[] v6StartHi, long[] v6StartLo,
      long[] v6EndHi, long[] v6EndLo, int networks) {
    this.v4Start = v4Start;
    this.v4End = v4End;
    this.v6StartHi = v6StartHi;
    this.v6StartLo = v6StartLo;
    this.v6EndHi = v6EndHi;
    this.v6EndLo = v6EndLo;
    this.networks = networks;
  }

  /** An empty set. */
  public static final IntervalSet EMPTY = of(List.of());

  /**
   * Builds a set from networks.
   *
   * @param ranges networks
   * @return set
   */
  public static IntervalSet of(List<IpRange> ranges) {
    List<long[]> four = new ArrayList<>();
    List<long[]> six = new ArrayList<>();
    for (IpRange range : ranges) {
      byte[] raw = range.address().getAddress();
      if (raw.length == 4) {
        long start = IpKeys.v4(raw);
        long size = 1L << (32 - range.prefix());
        four.add(new long[] {start, start + size - 1});
      } else {
        long hi = IpKeys.hi(raw);
        long lo = IpKeys.lo(raw);
        long endHi;
        long endLo;
        int prefix = range.prefix();
        if (prefix <= 64) {
          endHi = prefix == 0 ? -1L : hi | (prefix == 64 ? 0 : (-1L >>> prefix));
          endLo = -1L;
        } else {
          endHi = hi;
          endLo = lo | (prefix == 128 ? 0 : (-1L >>> (prefix - 64)));
        }
        six.add(new long[] {hi, lo, endHi, endLo});
      }
    }
    four.sort(Comparator.comparingLong(a -> a[0]));
    List<long[]> merged4 = new ArrayList<>();
    for (long[] interval : four) {
      long[] last = merged4.isEmpty() ? null : merged4.get(merged4.size() - 1);
      if (last != null && interval[0] <= last[1] + 1) {
        last[1] = Math.max(last[1], interval[1]);
      } else {
        merged4.add(interval.clone());
      }
    }
    six.sort((a, b) -> compare(a[0], a[1], b[0], b[1]));
    List<long[]> merged6 = new ArrayList<>();
    for (long[] interval : six) {
      long[] last = merged6.isEmpty() ? null : merged6.get(merged6.size() - 1);
      if (last != null && compare(interval[0], interval[1], last[2], last[3]) <= 0) {
        if (compare(interval[2], interval[3], last[2], last[3]) > 0) {
          last[2] = interval[2];
          last[3] = interval[3];
        }
      } else {
        merged6.add(interval.clone());
      }
    }
    return new IntervalSet(
        merged4.stream().mapToLong(a -> a[0]).toArray(),
        merged4.stream().mapToLong(a -> a[1]).toArray(),
        merged6.stream().mapToLong(a -> a[0]).toArray(),
        merged6.stream().mapToLong(a -> a[1]).toArray(),
        merged6.stream().mapToLong(a -> a[2]).toArray(),
        merged6.stream().mapToLong(a -> a[3]).toArray(),
        ranges.size());
  }

  private static int compare(long hiA, long loA, long hiB, long loB) {
    int c = Long.compareUnsigned(hiA, hiB);
    return c != 0 ? c : Long.compareUnsigned(loA, loB);
  }

  /**
   * Tests membership.
   *
   * @param address address
   * @return true if inside any network
   */
  public boolean contains(InetAddress address) {
    byte[] raw = IpRange.canonicalBytes(address);
    if (raw.length == 4) {
      long value = IpKeys.v4(raw);
      int index = Arrays.binarySearch(v4Start, value);
      if (index >= 0) {
        return true;
      }
      int candidate = -index - 2;
      return candidate >= 0 && value <= v4End[candidate];
    }
    long hi = IpKeys.hi(raw);
    long lo = IpKeys.lo(raw);
    int low = 0;
    int high = v6StartHi.length - 1;
    int candidate = -1;
    while (low <= high) {
      int mid = (low + high) >>> 1;
      if (compare(v6StartHi[mid], v6StartLo[mid], hi, lo) <= 0) {
        candidate = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return candidate >= 0 && compare(hi, lo, v6EndHi[candidate], v6EndLo[candidate]) <= 0;
  }

  /**
   * Returns the number of networks the set was built from.
   *
   * @return count
   */
  public int networks() {
    return networks;
  }
}
