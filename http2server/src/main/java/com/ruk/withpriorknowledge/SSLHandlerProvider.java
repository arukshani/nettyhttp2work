package com.ruk.withpriorknowledge;

import io.netty.handler.ssl.SslHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;

/**
 * Created by rukshani on 9/23/18.
 */
public class SSLHandlerProvider {


    // keytool  -genkey -noprompt -trustcacerts -keyalg RSA -alias cert -dname  maanadev.org -keypass 123456
    // -keystore mysslstore.jks -storepass 123456 -dname CN=maanadev.org
    //keytool -export -keystore mysslstore.jks -alias cert -file maanadev.org.cert
    //Move the maanadev.org.cert to /etc/ssl/certs/ directory
    //curl https://localhost:9090 -k

    private static final String PROTOCOL = "TLS";
    private static final String ALGORITHM_SUN_X509 = "SunX509";
    private static final String ALGORITHM = "ssl.KeyManagerFactory.algorithm";
    //    private static final String KEYSTORE = "ssl_certs/mysslstore.jks";
    public static final String KEYSTORE = "/home/rukshani/BallerinaWork/PERF_BAL/ballerinaKeystore.p12";
    //    private static final String KEYSTORE_TYPE = "JKS";
    public static final String KEYSTORE_TYPE = "PKCS12";
    //    private static final String KEYSTORE_PASSWORD = "123456";
//    private static final String CERT_PASSWORD = "123456";
    public static final String KEYSTORE_PASSWORD = "ballerina";
    public static final String CERT_PASSWORD = "ballerina";
    private static SSLContext serverSSLContext = null;

    public static SslHandler getSSLHandler() {
        SSLEngine sslEngine = null;
        if (serverSSLContext == null) {
            System.err.println("Server SSL context is null");
            System.exit(-1);
        } else {
            sslEngine = serverSSLContext.createSSLEngine();
            sslEngine.setUseClientMode(false);
            sslEngine.setNeedClientAuth(false);

        }
        return new SslHandler(sslEngine);
    }

    public static void initSSLContext() {

        System.out.println("Initiating SSL context");
        String algorithm = Security.getProperty(ALGORITHM);
        if (algorithm == null) {
            algorithm = ALGORITHM_SUN_X509;
        }
        KeyStore ks = null;
        InputStream inputStream = null;
        try {
            /*inputStream = new FileInputStream(
                    SSLHandlerProvider.class.getClassLoader().getResource(KEYSTORE).getFile());*/
            inputStream = new FileInputStream(new File(KEYSTORE));
            ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(inputStream, KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException e) {
            System.err.println("Cannot load the keystore file" + e.getMessage());
        } catch (CertificateException e) {
            System.err.println("Cannot get the certificate" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Something wrong with the SSL algorithm" + e.getMessage());
        } catch (KeyStoreException e) {
            System.err.println("Cannot initialize keystore" + e.getMessage());
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                System.err.println("Cannot close keystore file stream " + e.getMessage());
            }
        }
        try {
            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, CERT_PASSWORD.toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            TrustManager[] trustManagers = null;

            serverSSLContext = SSLContext.getInstance(PROTOCOL);
            serverSSLContext.init(keyManagers, trustManagers, null);

        } catch (Exception e) {
            System.err.println("Failed to initialize the server-side SSLContext" + e.getMessage());
        }
    }
}
