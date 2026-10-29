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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Colours console lines of the form {@code [*] tag      » text}. Velocity and Paper strip ANSI
 * codes from log files and from consoles without colour support, so the escapes only show up
 * where they render.
 */
public final class Ansi {
    public static final String RESET = "\u001b[0m";
    public static final String BOLD = "\u001b[1m";
    public static final String DIM = "\u001b[2m";
    public static final String RED = "\u001b[91m";
    public static final String DARK_RED = "\u001b[31m";
    public static final String GREEN = "\u001b[92m";
    public static final String YELLOW = "\u001b[93m";
    public static final String CYAN = "\u001b[96m";
    public static final String MAGENTA = "\u001b[95m";
    public static final String GRAY = "\u001b[90m";
    public static final String WHITE = "\u001b[97m";
    public static final String MOON = "\u001b[38;5;229m";

    private static final Pattern LINE = Pattern.compile("^\\[(.)] (\\S+)(\\s*)» ?(.*)$", Pattern.DOTALL);
    private static final Pattern KEY = Pattern.compile("(?<=^|\\s)([a-z][a-z0-9/_-]*):(?!//)(\\S+)");

    private Ansi() {}

    /** Marker colour: + ok, * info, ~ routing, ! warning, - skipped/dropped, x error. */
    public static String markerColor(char marker) {
        return switch (marker) {
            case '+' -> GREEN;
            case '!' -> YELLOW;
            case 'x' -> RED;
            case '-' -> DARK_RED;
            case '~' -> MAGENTA;
            default -> CYAN;
        };
    }

    /** Colours one line; text in any other shape is returned unchanged. */
    public static String line(String text) {
        Matcher m = LINE.matcher(text);
        if (!m.matches()) return text;
        char marker = m.group(1).charAt(0);
        String color = markerColor(marker);
        String body = KEY.matcher(m.group(4)).replaceAll(match ->
            Matcher.quoteReplacement(GRAY + match.group(1) + ":" + WHITE + match.group(2) + RESET));
        body = body.replace("──▶", YELLOW + "──▶" + RESET).replace("→", GRAY + "→" + RESET);
        // log4j placeholders: values are shown bright.
        body = body.replace("{}", WHITE + "{}" + RESET);
        if (marker == 'x') body = RED + body + RESET;
        return BOLD + color + "[" + marker + "]" + RESET + " " + BOLD + WHITE + m.group(2) + RESET + m.group(3)
            + GRAY + "» " + RESET + body;
    }
}
