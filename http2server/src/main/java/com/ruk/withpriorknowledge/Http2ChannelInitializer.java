package com.ruk.withpriorknowledge;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerUpgradeHandler;
import io.netty.handler.codec.http2.CleartextHttp2ServerUpgradeHandler;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.codec.http2.Http2ServerUpgradeCodec;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.AsciiString;
import io.netty.util.ReferenceCountUtil;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;


/**
 * Created by rukshani on 9/22/18.
 */
public class Http2ChannelInitializer extends ChannelInitializer<SocketChannel> {

    public static final String KEYSTORE = "/home/rukshani/BallerinaWork/PERF_BAL/ballerinaKeystore.p12";
    //    private static final String KEYSTORE_TYPE = "JKS";
    public static final String KEYSTORE_TYPE = "PKCS12";
    //    private static final String KEYSTORE_PASSWORD = "123456";
//    private static final String CERT_PASSWORD = "123456";
    public static final String KEYSTORE_PASSWORD = "ballerina";
    public static final String CERT_PASSWORD = "ballerina";

    private static final HttpServerUpgradeHandler.UpgradeCodecFactory upgradeCodecFactory =
            protocol -> {
                if (AsciiString.contentEquals(Http2CodecUtil.HTTP_UPGRADE_PROTOCOL_NAME, protocol)) {
                    return new Http2ServerUpgradeCodec(new HelloWorldHttp2HandlerBuilder().build());
                } else {
                    return null;
                }
            };

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        boolean isSSL = true;
        if (isSSL) {
            configureSsl(ch);
        } else {
            configureH2CWithPriorKnowledge(ch.pipeline());
        }
    }

    /**
     * Configure the pipeline for TLS NPN negotiation to HTTP/2.
     */
    private void configureSsl(SocketChannel ch) throws CertificateException, SSLException {
        //  ch.pipeline().addLast(getSSLHandler(), new Http2OrHttpHandler());
        //ch.pipeline().addLast(configureSSL().newHandler(ch.alloc()), new Http2OrHttpHandler());
        ch.pipeline().addLast(configureSSL().newHandler(ch.alloc()), new Http2OrHttpHandler());
    }

    private void configureH2CWithPriorKnowledge(ChannelPipeline pipeline) {
        final HttpServerCodec sourceCodec = new HttpServerCodec();
        final HttpServerUpgradeHandler upgradeHandler = new HttpServerUpgradeHandler(sourceCodec, upgradeCodecFactory);
        final CleartextHttp2ServerUpgradeHandler cleartextHttp2ServerUpgradeHandler =
                new CleartextHttp2ServerUpgradeHandler(sourceCodec, upgradeHandler,
                                                       new HelloWorldHttp2HandlerBuilder().build());

        pipeline.addLast(cleartextHttp2ServerUpgradeHandler);
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

        pipeline.addLast(new UserEventLogger());
    }

    /**
     * Class that logs any User Events triggered on this channel.
     */
    private static class UserEventLogger extends ChannelInboundHandlerAdapter {

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            System.out.println("UserEventLogger's channel read");
            ctx.fireChannelRead(msg);
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
            System.out.println("User Event Triggered: " + evt);
            ctx.fireUserEventTriggered(evt);
        }
    }

    //This is just for testing purpose
    private SslContext configureSSL()
            throws SSLException, CertificateException {
        // Configure SSL.
        SslContext sslCtx = null;
        try {

            boolean SSL = true;
            if (SSL) {
                KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
                ks.load(new FileInputStream(new File(KEYSTORE)), KEYSTORE_PASSWORD.toCharArray());
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, CERT_PASSWORD.toCharArray());
                SslProvider provider = OpenSsl.isAlpnSupported() ? SslProvider.OPENSSL : SslProvider.JDK;
                System.out.println("OpenSsl.isAlpnSupported():" + OpenSsl.isAlpnSupported());
                SelfSignedCertificate ssc = new SelfSignedCertificate();
                sslCtx = SslContextBuilder.forServer(kmf)
                        .sslProvider(provider)
                        /* NOTE: the cipher filter may not include all ciphers required by the HTTP/2 specification.
                         * Please refer to the HTTP/2 specification for cipher requirements. */
                        .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                        .applicationProtocolConfig(new ApplicationProtocolConfig(
                                ApplicationProtocolConfig.Protocol.ALPN,
                                // NO_ADVERTISE is currently the only mode supported by both OpenSsl and JDK providers.
                                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                                // ACCEPT is currently the only mode supported by both OpenSsl and JDK providers.
                                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                                ApplicationProtocolNames.HTTP_2,
                                ApplicationProtocolNames.HTTP_1_1))
                        .build();
            } else {
                sslCtx = null;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return sslCtx;
    }

    private SslContext minimalSSL() throws CertificateException, SSLException {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        SslContext sslCtx = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
                .build();
        return sslCtx;
    }

    //This is just for testing purpose
    private SslContext testSSL() throws SSLException, CertificateException {
        // Configure SSL.
        final SslContext sslCtx;
        boolean SSL = true;
        if (SSL) {
            SelfSignedCertificate ssc = new SelfSignedCertificate();
            sslCtx = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey())
                    /* NOTE: the cipher filter may not include all ciphers required by the HTTP/2 specification.
                     * Please refer to the HTTP/2 specification for cipher requirements. */
                    .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                    .applicationProtocolConfig(new ApplicationProtocolConfig(
                            ApplicationProtocolConfig.Protocol.ALPN,
                            // NO_ADVERTISE is currently the only mode supported by both OpenSsl and JDK providers.
                            ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                            // ACCEPT is currently the only mode supported by both OpenSsl and JDK providers.
                            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                            ApplicationProtocolNames.HTTP_2,
                            ApplicationProtocolNames.HTTP_1_1))
                    .build();
        } else {
            sslCtx = null;
        }

        return sslCtx;
    }
}
