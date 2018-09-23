package com.ruk.justupgrade;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2ServerUpgradeCodec;
import io.netty.util.AsciiString;
import io.netty.util.ReferenceCountUtil;

/**
 * Created by rukshani on 9/22/18.
 */
public class Http2ChannelInitializer extends ChannelInitializer<SocketChannel> {

    private static final HttpServerUpgradeHandler.UpgradeCodecFactory upgradeCodecFactory =
            new HttpServerUpgradeHandler.UpgradeCodecFactory() {
                @Override
                public HttpServerUpgradeHandler.UpgradeCodec newUpgradeCodec(CharSequence protocol) {
                    if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
                        return new Http2ServerUpgradeCodec(
                                Http2FrameCodecBuilder.forServer().build(), new HelloWorldHttp2Handler());
                    } else {
                        System.err.println("Not upgraded:" + protocol);
                        return null;
                    }
                }
            };

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        configureH2CPipeline(ch.pipeline());
    }

    /* HTTP/2 is run over cleartext TCP. This identifier is used in the HTTP/1.1 Upgrade
     header field and in any place where HTTP/2 over TCP is identified.
     The "h2c" string is reserved from the ALPN identifier space but describes a protocol that does not use TLS*/
    private void configureH2CPipeline(ChannelPipeline pipeline) {
        final HttpServerCodec sourceCodec = new HttpServerCodec();
        pipeline.addLast(sourceCodec);
        //sourceCodec will be removed from the pipeline if the upgrade is successful
        pipeline.addLast(new HttpServerUpgradeHandler(sourceCodec, upgradeCodecFactory));
        pipeline.addLast(new SimpleChannelInboundHandler<HttpMessage>() {
            @Override
            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
                // If this handler is hit then no upgrade has been attempted and the client is just talking HTTP.
                System.err.println("Directly talking: " + msg.protocolVersion() + " (no upgrade was attempted)");
                ChannelPipeline pipeline = ctx.pipeline();
                ChannelHandlerContext thisCtx = pipeline.context(this);
                pipeline.addAfter(thisCtx.name(), null, new HelloWorldHttp1Handler("Direct. No Upgrade Attempted."));
                pipeline.replace(this, null, new HttpObjectAggregator(16 * 1024));
                ctx.fireChannelRead(ReferenceCountUtil.retain(msg));
            }
        });
    }
}
