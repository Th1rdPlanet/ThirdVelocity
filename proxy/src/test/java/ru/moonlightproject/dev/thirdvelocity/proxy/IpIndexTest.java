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

package ru.moonlightproject.dev.thirdvelocity.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ru.moonlightproject.dev.thirdvelocity.api.ban.BanTarget;
import ru.moonlightproject.dev.thirdvelocity.api.net.IpRange;
import ru.moonlightproject.dev.thirdvelocity.proxy.intel.IpListManager;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.Durations;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.IntervalSet;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.PrefixIndex;

class IpIndexTest {

  private static java.net.InetAddress ip(String text) {
    return IpRange.parseLiteral(text);
  }

  @Test
  void rangeNormalizesAndContains() {
    IpRange range = IpRange.parse("10.1.2.3/8");
    assertEquals("10.0.0.0/8", range.toString());
    assertTrue(range.contains(ip("10.255.0.1")));
    assertFalse(range.contains(ip("11.0.0.1")));
    assertTrue(IpRange.parse("2001:db8::/32").contains(ip("2001:db8:ffff::1")));
    assertTrue(IpRange.parse("1.2.3.4").contains(ip("::ffff:1.2.3.4")));
    assertThrows(IllegalArgumentException.class, () -> IpRange.parse("example.com"));
    assertThrows(IllegalArgumentException.class, () -> IpRange.parse("1.2.3.4/33"));
  }

  @Test
  void prefixIndexPrefersMostSpecific() {
    PrefixIndex<String> index = PrefixIndex.<String>builder()
        .put(IpRange.parse("10.0.0.0/8"), "wide")
        .put(IpRange.parse("10.1.0.0/16"), "narrow")
        .put(IpRange.parse("2001:db8::/32"), "v6")
        .put(IpRange.parse("2001:db8::1"), "host6")
        .build();
    assertEquals("narrow", index.longestMatch(ip("10.1.2.3")));
    assertEquals("wide", index.longestMatch(ip("10.2.0.1")));
    assertEquals("host6", index.longestMatch(ip("2001:db8::1")));
    assertEquals("v6", index.longestMatch(ip("2001:db8::2")));
    assertNull(index.longestMatch(ip("8.8.8.8")));
  }

  @Test
  void intervalSetMergesAndSearches() {
    IntervalSet set = IntervalSet.of(List.of(IpRange.parse("1.0.0.0/24"), IpRange.parse("1.0.1.0/24"),
        IpRange.parse("5.5.5.5"), IpRange.parse("2a00::/16")));
    assertTrue(set.contains(ip("1.0.1.255")));
    assertFalse(set.contains(ip("1.0.2.0")));
    assertTrue(set.contains(ip("5.5.5.5")));
    assertFalse(set.contains(ip("5.5.5.6")));
    assertTrue(set.contains(ip("2a00:1::1")));
    assertFalse(set.contains(ip("2a01::1")));
  }

  @Test
  void durations() {
    assertEquals(Duration.ofDays(1).plusHours(12), Durations.parse("1d12h"));
    assertEquals(Duration.ofDays(60), Durations.parse("2mo"));
    assertEquals(Duration.ofMinutes(30), Durations.parse("30m"));
    assertEquals(Duration.ofSeconds(90), Durations.parse("90"));
    assertFalse(Durations.isDuration("griefing"));
  }

  @Test
  void banTargets() {
    assertEquals("ip", BanTarget.parse("cidr", "1.2.3.0/24").kind());
    assertEquals("notch", BanTarget.parse("name", "Notch").value());
    assertEquals("13335", BanTarget.parse("asn", "AS13335").value());
    assertEquals("RU", BanTarget.parse("country", "ru").value());
    assertThrows(IllegalArgumentException.class, () -> BanTarget.parse("name", "bad name"));
  }

  @Test
  void listParser(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("list.txt");
    Files.writeString(file, "# comment\n1.2.3.4\n10.0.0.0/8 ; inline\n192.168.0.0-192.168.0.255\ngarbage\n");
    List<IpRange> ranges = IpListManager.parse(file, IpListManager.Format.PLAIN);
    IntervalSet set = IntervalSet.of(ranges);
    assertTrue(set.contains(ip("1.2.3.4")));
    assertTrue(set.contains(ip("10.9.9.9")));
    assertTrue(set.contains(ip("192.168.0.200")));
    assertFalse(set.contains(ip("192.168.1.1")));
    Path json = dir.resolve("drop.json");
    Files.writeString(json, "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL1\"}\n{\"type\":\"metadata\"}\n");
    assertEquals(1, IpListManager.parse(json, IpListManager.Format.SPAMHAUS_JSON).size());
  }
}
