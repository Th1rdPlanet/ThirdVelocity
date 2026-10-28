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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import java.util.concurrent.atomic.LongAdder;

/**
 * Counts bytes and frames on client channels without looking at payloads. Shared by all
 * channels; sits at the head of the pipeline so it sees the wire-level (compressed, encrypted)
 * sizes.
 */
@ChannelHandler.Sharable
public final class TrafficCounter extends ChannelDuplexHandler {

  final LongAdder inboundBytes = new LongAdder();
  final LongAdder outboundBytes = new LongAdder();
  final LongAdder outboundPackets = new LongAdder();
  final LongAdder open = new LongAdder();

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    open.increment();
    super.channelActive(ctx);
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    open.decrement();
    super.channelInactive(ctx);
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    if (msg instanceof ByteBuf buf) {
      inboundBytes.add(buf.readableBytes());
    }
    super.channelRead(ctx, msg);
  }

  @Override
  public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
    if (msg instanceof ByteBuf buf) {
      outboundBytes.add(buf.readableBytes());
      outboundPackets.increment();
    }
    super.write(ctx, msg, promise);
  }
}
