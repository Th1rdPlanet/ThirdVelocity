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

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import ru.moonlightproject.dev.thirdvelocity.proxy.util.ConfigNode;

/**
 * Player-facing texts from {@code messages.yml}. Values are MiniMessage; placeholders are
 * inserted as unparsed text, so names and reasons cannot inject tags.
 */
public final class Messages {

  private final ConfigNode node;

  Messages(ConfigNode node) {
    this.node = node;
  }

  /**
   * Renders a message.
   *
   * @param key message key
   * @param placeholders alternating placeholder names and values
   * @return component
   */
  public Component render(String key, String... placeholders) {
    TagResolver.Builder resolver = TagResolver.builder();
    for (int i = 0; i + 1 < placeholders.length; i += 2) {
      resolver.resolver(Placeholder.unparsed(placeholders[i], placeholders[i + 1] == null ? "" : placeholders[i + 1]));
    }
    return MiniMessage.miniMessage().deserialize(node.string(key, "<red>" + key), resolver.build());
  }

  /**
   * Returns the raw text of a message.
   *
   * @param key key
   * @return text
   */
  public String raw(String key) {
    return node.string(key, key);
  }
}
