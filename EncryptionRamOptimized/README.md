# EncryptionRamOptimized

Utility per cifrare o decifrare file di grandi dimensioni usando PKCS#7 (CMS) con Bouncy Castle.

## Compilazione

Installare `openjdk-21-jdk` e le librerie `libbcprov-java` e `libbcpkix-java`.
Poi compilare:

```bash
javac -cp /usr/share/java/bcprov-1.77.jar:/usr/share/java/bcpkix-1.77.jar src/main/java/com/example/encryption/FileEncryptor.java -d target/classes
```

## Uso

```
java -cp target/classes:/usr/share/java/bcprov-1.77.jar:/usr/share/java/bcpkix-1.77.jar com.example.encryption.FileEncryptor encrypt cert.pem aes-256-cbc input.bin output.p7
java -cp target/classes:/usr/share/java/bcprov-1.77.jar:/usr/share/java/bcpkix-1.77.jar com.example.encryption.FileEncryptor decrypt key.p12 password input.p7 output.bin
```

Algoritmi supportati: `aes-256-cbc`, `des-ede3-cbc`, `bf-cbc`, `des-cbc`, `aes-256-gcm`.
