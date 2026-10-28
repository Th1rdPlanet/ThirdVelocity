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

package ru.moonlightproject.dev.thirdvelocity.proxy.protection;

import it.unimi.dsi.fastutil.longs.LongOpenHashSet;
import java.net.InetAddress;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IpKeys;

/** Compact concurrent set of addresses (8 bytes per entry). */
public final class AddressSet {

  private final LongOpenHashSet keys = new LongOpenHashSet();
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  /**
   * Adds an address.
   *
   * @param address address
   */
  public void add(InetAddress address) {
    long key = IpKeys.key(address);
    lock.writeLock().lock();
    try {
      keys.add(key);
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Tests membership.
   *
   * @param address address
   * @return true if present
   */
  public boolean contains(InetAddress address) {
    long key = IpKeys.key(address);
    lock.readLock().lock();
    try {
      return keys.contains(key);
    } finally {
      lock.readLock().unlock();
    }
  }

  /**
   * Replaces the contents.
   *
   * @param addresses new contents
   */
  public void replace(Iterable<InetAddress> addresses) {
    LongOpenHashSet next = new LongOpenHashSet();
    for (InetAddress address : addresses) {
      next.add(IpKeys.key(address));
    }
    lock.writeLock().lock();
    try {
      keys.clear();
      keys.addAll(next);
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Returns the size.
   *
   * @return entries
   */
  public int size() {
    lock.readLock().lock();
    try {
      return keys.size();
    } finally {
      lock.readLock().unlock();
    }
  }
}
