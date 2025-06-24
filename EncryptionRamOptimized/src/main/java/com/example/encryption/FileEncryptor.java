package com.example.encryption;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.util.io.Streams;

import java.security.cert.CertificateException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;

import java.security.KeyStore;

public class FileEncryptor {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void encrypt(String certificatePem, String algorithm, String inputFile, String outputFile) throws Exception {
        X509Certificate cert = loadCertificate(certificatePem);

        CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
        ASN1ObjectIdentifier oid = algorithmOid(algorithm);
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(oid).setProvider("BC").build();

        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile));
             InputStream in = new BufferedInputStream(new FileInputStream(inputFile));
             OutputStream encryptedOut = gen.open(out, encryptor)) {
            Streams.pipeAll(in, encryptedOut);
        }
    }

    public static void decrypt(String p12File, String password, String inputFile, String outputFile) throws Exception {
        PrivateKey priv = loadPrivateKeyFromP12(p12File, password);
        CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(new BufferedInputStream(new FileInputStream(inputFile)));
        RecipientInformationStore recipients = parser.getRecipientInfos();
        RecipientInformation recipient = recipients.getRecipients().iterator().next();

        try (InputStream data = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(priv).setProvider("BC")).getContentStream();
             OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            Streams.pipeAll(data, out);
        } finally {
            parser.close();
        }
    }

    private static ASN1ObjectIdentifier algorithmOid(String alg) {
        return switch (alg.toLowerCase()) {
            case "aes-256-cbc" -> new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.42");
            case "aes-256-gcm" -> new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.46");
            case "des-ede3-cbc" -> new ASN1ObjectIdentifier("1.2.840.113549.3.7");
            case "des-cbc" -> new ASN1ObjectIdentifier("1.3.14.3.2.7");
            case "bf-cbc" -> new ASN1ObjectIdentifier("1.3.6.1.4.1.3029.1.2");
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        };
    }

    private static X509Certificate loadCertificate(String file) throws IOException, CertificateException {
        try (InputStream in = new FileInputStream(file)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        }
    }

    private static PrivateKey loadPrivateKeyFromP12(String file, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(file)) {
            ks.load(in, password != null ? password.toCharArray() : null);
        }
        String alias = ks.aliases().nextElement();
        return (PrivateKey) ks.getKey(alias, password != null ? password.toCharArray() : null);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: encrypt|decrypt ...");
            return;
        }
        switch (args[0]) {
            case "encrypt" -> {
                if (args.length != 5) {
                    System.err.println("encrypt <certPem> <algorithm> <inputFile> <outputFile>");
                    return;
                }
                encrypt(args[1], args[2], args[3], args[4]);
            }
            case "decrypt" -> {
                if (args.length != 5) {
                    System.err.println("decrypt <p12File> <password> <inputFile> <outputFile>");
                    return;
                }
                decrypt(args[1], args[2], args[3], args[4]);
            }
            default -> System.err.println("Unknown command");
        }
    }
}

