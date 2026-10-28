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

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Read-only view of a YAML file merged over its bundled defaults. Missing keys fall back to the
 * defaults; wrong types and out-of-range values throw {@link ConfigException} with the full path,
 * so a broken config fails loudly at startup or reload.
 */
public final class ConfigNode {

  private final String path;
  private final Map<String, Object> values;

  private ConfigNode(String path, Map<String, Object> values) {
    this.path = path;
    this.values = values;
  }

  /**
   * Loads {@code file}, writing the bundled resource there first if the file does not exist.
   *
   * @param file config file
   * @param resource classpath resource with defaults
   * @return merged node
   * @throws IOException if reading fails
   */
  public static ConfigNode load(Path file, String resource) throws IOException {
    Map<String, Object> defaults;
    try (InputStream in = ConfigNode.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IOException("Missing bundled resource " + resource);
      }
      byte[] bytes = in.readAllBytes();
      if (Files.notExists(file)) {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, bytes);
      }
      defaults = parse(new String(bytes, StandardCharsets.UTF_8), resource);
    }
    Map<String, Object> user;
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      StringBuilder text = new StringBuilder();
      char[] buffer = new char[8192];
      int read;
      while ((read = reader.read(buffer)) >= 0) {
        text.append(buffer, 0, read);
      }
      user = parse(text.toString(), file.toString());
    }
    return new ConfigNode(file.getFileName().toString(), merge(defaults, user));
  }

  /**
   * Creates a node from a map (tests and nested list entries).
   *
   * @param path display path
   * @param values values
   * @return node
   */
  public static ConfigNode of(String path, Map<String, Object> values) {
    return new ConfigNode(path, values);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> parse(String text, String source) {
    Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
    Object root = yaml.load(text);
    if (root == null) {
      return new LinkedHashMap<>();
    }
    if (!(root instanceof Map<?, ?>)) {
      throw new ConfigException(source + ": the top level must be a mapping");
    }
    return (Map<String, Object>) root;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> merge(Map<String, Object> defaults, Map<String, Object> user) {
    Map<String, Object> result = new LinkedHashMap<>(defaults);
    for (Map.Entry<String, Object> entry : user.entrySet()) {
      Object base = result.get(entry.getKey());
      if (base instanceof Map<?, ?> baseMap && entry.getValue() instanceof Map<?, ?> userMap) {
        result.put(entry.getKey(), merge((Map<String, Object>) baseMap, (Map<String, Object>) userMap));
      } else {
        result.put(entry.getKey(), entry.getValue());
      }
    }
    return result;
  }

  private String at(String key) {
    return path + ": " + key;
  }

  /**
   * Returns the keys of this section.
   *
   * @return keys in file order
   */
  public Set<String> keys() {
    return Collections.unmodifiableSet(values.keySet());
  }

  /**
   * Reports whether a key exists.
   *
   * @param key key
   * @return true if present
   */
  public boolean has(String key) {
    return values.containsKey(key) && values.get(key) != null;
  }

  /**
   * Returns a nested section; an absent section is empty.
   *
   * @param key key
   * @return section
   */
  @SuppressWarnings("unchecked")
  public ConfigNode section(String key) {
    Object value = values.get(key);
    if (value == null) {
      return new ConfigNode(path + "." + key, Map.of());
    }
    if (!(value instanceof Map<?, ?> map)) {
      throw new ConfigException(at(key) + " must be a section");
    }
    return new ConfigNode(path + "." + key, (Map<String, Object>) map);
  }

  /**
   * Returns a list of sections.
   *
   * @param key key
   * @return sections
   */
  @SuppressWarnings("unchecked")
  public List<ConfigNode> sections(String key) {
    Object value = values.get(key);
    if (value == null) {
      return List.of();
    }
    if (!(value instanceof List<?> list)) {
      throw new ConfigException(at(key) + " must be a list");
    }
    List<ConfigNode> result = new ArrayList<>();
    for (int i = 0; i < list.size(); i++) {
      if (!(list.get(i) instanceof Map<?, ?> map)) {
        throw new ConfigException(at(key) + "[" + i + "] must be a section");
      }
      result.add(new ConfigNode(path + "." + key + "[" + i + "]", (Map<String, Object>) map));
    }
    return result;
  }

  /**
   * Returns a boolean.
   *
   * @param key key
   * @param fallback value if absent
   * @return value
   */
  public boolean bool(String key, boolean fallback) {
    Object value = values.get(key);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Boolean b) {
      return b;
    }
    throw new ConfigException(at(key) + " must be true or false");
  }

  /**
   * Returns an integer within bounds.
   *
   * @param key key
   * @param fallback value if absent
   * @param min minimum
   * @param max maximum
   * @return value
   */
  public int integer(String key, int fallback, int min, int max) {
    long value = longValue(key, fallback, min, max);
    return (int) value;
  }

  /**
   * Returns a long within bounds.
   *
   * @param key key
   * @param fallback value if absent
   * @param min minimum
   * @param max maximum
   * @return value
   */
  public long longValue(String key, long fallback, long min, long max) {
    Object value = values.get(key);
    long result;
    if (value == null) {
      result = fallback;
    } else if (value instanceof Number number && !(value instanceof Double) && !(value instanceof Float)) {
      result = number.longValue();
    } else {
      throw new ConfigException(at(key) + " must be an integer");
    }
    if (result < min || result > max) {
      throw new ConfigException(at(key) + " must be between " + min + " and " + max);
    }
    return result;
  }

  /**
   * Returns a decimal within bounds.
   *
   * @param key key
   * @param fallback value if absent
   * @param min minimum
   * @param max maximum
   * @return value
   */
  public double decimal(String key, double fallback, double min, double max) {
    Object value = values.get(key);
    double result;
    if (value == null) {
      result = fallback;
    } else if (value instanceof Number number) {
      result = number.doubleValue();
    } else {
      throw new ConfigException(at(key) + " must be a number");
    }
    if (result < min || result > max || Double.isNaN(result)) {
      throw new ConfigException(at(key) + " must be between " + min + " and " + max);
    }
    return result;
  }

  /**
   * Returns a string.
   *
   * @param key key
   * @param fallback value if absent
   * @return value
   */
  public String string(String key, String fallback) {
    Object value = values.get(key);
    if (value == null) {
      return fallback;
    }
    if (value instanceof String || value instanceof Number || value instanceof Boolean) {
      return String.valueOf(value);
    }
    throw new ConfigException(at(key) + " must be a string");
  }

  /**
   * Returns an enum constant, case-insensitive.
   *
   * @param key key
   * @param fallback value if absent
   * @param <E> enum type
   * @return value
   */
  public <E extends Enum<E>> E enumValue(String key, E fallback) {
    String raw = string(key, fallback.name()).trim().toUpperCase(Locale.ROOT).replace('-', '_');
    try {
      return Enum.valueOf(fallback.getDeclaringClass(), raw);
    } catch (IllegalArgumentException e) {
      StringBuilder allowed = new StringBuilder();
      for (E constant : fallback.getDeclaringClass().getEnumConstants()) {
        allowed.append(allowed.isEmpty() ? "" : ", ").append(constant.name());
      }
      throw new ConfigException(at(key) + " must be one of " + allowed);
    }
  }

  /**
   * Returns a list of strings; a single string becomes a one-element list.
   *
   * @param key key
   * @return values
   */
  public List<String> strings(String key) {
    Object value = values.get(key);
    if (value == null) {
      return List.of();
    }
    if (value instanceof List<?> list) {
      List<String> result = new ArrayList<>(list.size());
      for (Object item : list) {
        if (item == null || item instanceof Map<?, ?> || item instanceof List<?>) {
          throw new ConfigException(at(key) + " must contain only strings");
        }
        result.add(String.valueOf(item));
      }
      return result;
    }
    return List.of(String.valueOf(value));
  }

  /**
   * Returns a map of string keys to integers.
   *
   * @param key key
   * @return values
   */
  public Map<String, Integer> integerMap(String key) {
    ConfigNode section = section(key);
    Map<String, Integer> result = new LinkedHashMap<>();
    for (String name : section.keys()) {
      result.put(name, section.integer(name, 0, -1_000_000, 1_000_000));
    }
    return result;
  }

  /**
   * Returns a duration written as {@code 30s}, {@code 15m}, {@code 12h}, {@code 7d} or plain
   * seconds.
   *
   * @param key key
   * @param fallback value if absent
   * @return duration
   */
  public Duration duration(String key, Duration fallback) {
    Object value = values.get(key);
    if (value == null) {
      return fallback;
    }
    try {
      return Durations.parse(String.valueOf(value));
    } catch (IllegalArgumentException e) {
      throw new ConfigException(at(key) + ": " + e.getMessage());
    }
  }

  /** Configuration error with the offending path. */
  public static final class ConfigException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message message
     */
    public ConfigException(String message) {
      super(message);
    }
  }
}
