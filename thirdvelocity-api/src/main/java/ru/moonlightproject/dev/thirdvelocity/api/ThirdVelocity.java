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

package ru.moonlightproject.dev.thirdvelocity.api;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Entry point of the ThirdVelocity API.
 *
 * <p>The proxy installs the implementation before plugins are loaded, so a plugin may call
 * {@link #api()} from its constructor or initialization event. Plugins that must also run on the
 * upstream Velocity should check {@link #isPresent()} (or catch {@link NoClassDefFoundError} when
 * the API is not on the class path at all).</p>
 */
public final class ThirdVelocity {

  private static final AtomicReference<ThirdVelocityApi> INSTANCE = new AtomicReference<>();

  private ThirdVelocity() {
  }

  /**
   * Returns the running API.
   *
   * @return the API implementation
   * @throws IllegalStateException if the proxy is not ThirdVelocity or the core is not started
   */
  public static ThirdVelocityApi api() {
    ThirdVelocityApi api = INSTANCE.get();
    if (api == null) {
      throw new IllegalStateException("ThirdVelocity core is not running");
    }
    return api;
  }

  /**
   * Returns the running API if present.
   *
   * @return the API, or empty on a proxy without ThirdVelocity
   */
  public static Optional<ThirdVelocityApi> find() {
    return Optional.ofNullable(INSTANCE.get());
  }

  /**
   * Reports whether the ThirdVelocity core is running.
   *
   * @return true when {@link #api()} will succeed
   */
  public static boolean isPresent() {
    return INSTANCE.get() != null;
  }

  /**
   * Installs the implementation. Called once by the proxy; plugins must not call it.
   *
   * @param api implementation
   */
  public static void install(ThirdVelocityApi api) {
    if (!INSTANCE.compareAndSet(null, api)) {
      throw new IllegalStateException("ThirdVelocity API is already installed");
    }
  }

  /**
   * Removes the implementation on proxy shutdown. Plugins must not call it.
   *
   * @param api implementation previously installed
   */
  public static void uninstall(ThirdVelocityApi api) {
    INSTANCE.compareAndSet(api, null);
  }
}
