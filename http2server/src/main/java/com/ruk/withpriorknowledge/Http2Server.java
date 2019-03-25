package com.ruk.withpriorknowledge;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import java.net.InetSocketAddress;

/**
 * Created by rukshani on 9/22/18.
 */
public class Http2Server {
    private final int port;

    public Http2Server(int port) {
        this.port = port;
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: " + Http2Server.class.getSimpleName() + " <port>");
            return;
        }
        int port = Integer.parseInt(args[0]);
        new Http2Server(port).start();
    }

    public void start() throws Exception {

        EventLoopGroup group = new NioEventLoopGroup();

        // Load the certificates and initiate the SSL Context
//        SSLHandlerProvider.initSSLContext();

        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(group)
                    .channel(NioServerSocketChannel.class)
                    .localAddress(new InetSocketAddress(port))
                    .childHandler(new Http2ChannelInitializer());

            ChannelFuture f = b.bind().sync();
            System.out.println(Http2Server.class.getName() +
                    " started and listening for connections on " + f.channel().localAddress());
            f.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully().sync();
        }
    }
}
