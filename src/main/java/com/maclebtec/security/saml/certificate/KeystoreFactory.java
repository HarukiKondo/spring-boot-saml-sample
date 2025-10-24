package com.maclebtec.security.saml.certificate;

import lombok.SneakyThrows;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * キーストア操作を行うためのファクトリクラス
 * 
 * このクラスは、SAML認証で使用するX.509証明書とRSA秘密鍵を
 * Javaキーストア（JKS形式）に格納・操作するための機能を提供します。
 * 
 * 主な機能：
 * - 証明書ファイルと秘密鍵ファイルからキーストアを作成
 * - 既存のキーストアに新しい証明書と秘密鍵のペアを追加
 * - リソースファイル（クラスパスまたはファイルシステム）からの証明書・鍵の読み込み
 * 
 * 使用例：
 * KeystoreFactory factory = new KeystoreFactory();
 * KeyStore keystore = factory.loadKeystore(
 *     "classpath:saml/localhost.cert", 
 *     "classpath:saml/localhost.key.der", 
 *     "localhost", 
 *     "password"
 * );
 */
public class KeystoreFactory {

    /**
     * リソースローダー（ファイルやクラスパスからリソースを読み込むために使用）
     * Springのリソース抽象化を利用して、様々な場所からファイルを読み込めます
     */
    private ResourceLoader resourceLoader;

    /**
     * デフォルトコンストラクタ
     * DefaultResourceLoaderを使用してリソースローダーを初期化します
     * 
     * DefaultResourceLoaderは以下のリソースプレフィックスに対応：
     * - classpath: クラスパス内のリソース
     * - file: ファイルシステム上のファイル
     * - http/https: URL経由でのリソース
     */
    public KeystoreFactory() {
        resourceLoader = new DefaultResourceLoader();
    }

    /**
     * カスタムリソースローダーを指定するコンストラクタ
     * テスト時や特殊な環境でカスタムのリソースローダーを使用する場合に利用
     * 
     * @param resourceLoader カスタムのリソースローダー
     */
    public KeystoreFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    /**
     * 証明書と秘密鍵からキーストアを作成します
     * 
     * このメソッドは、指定されたリソース場所から証明書と秘密鍵を読み込み、
     * 新しいJKSキーストアを作成して両方を格納します。
     * SAML認証で使用する主要なメソッドです。
     * 
     * @param certResourceLocation 証明書ファイルのリソース場所（例: "classpath:saml/localhost.cert"）
     * @param privateKeyResourceLocation 秘密鍵ファイルのリソース場所（例: "classpath:saml/localhost.key.der"）
     * @param alias キーストア内でのエイリアス名（証明書と鍵のペアを識別するための名前）
     * @param keyPassword キーのパスワード（秘密鍵を保護するためのパスワード）
     * @return 作成されたキーストア（証明書と秘密鍵のペアが格納済み）
     */
    @SneakyThrows
    public KeyStore loadKeystore(String certResourceLocation, String privateKeyResourceLocation, String alias, String keyPassword) {
        // 1. 空のJKSキーストアを作成
        KeyStore keystore = createEmptyKeystore();
        // 2. 指定された場所からX.509証明書を読み込み
        X509Certificate cert = loadCert(certResourceLocation);
        // 3. 指定された場所からRSA秘密鍵を読み込み
        RSAPrivateKey privateKey = loadPrivateKey(privateKeyResourceLocation);
        // 4. 証明書と秘密鍵をキーストアに追加
        addKeyToKeystore(keystore, cert, privateKey, alias, keyPassword);
        return keystore;
    }

    /**
     * キーストアに証明書と秘密鍵のペアを追加します
     * 
     * このメソッドは、既存のキーストアに新しい証明書と秘密鍵のペアを追加します。
     * 証明書チェーンも同時に設定され、パスワード保護が適用されます。
     * 
     * @param keyStore 対象のキーストア（証明書と鍵を追加する先）
     * @param cert X.509証明書（公開鍵を含む証明書）
     * @param privateKey RSA秘密鍵（対応する秘密鍵）
     * @param alias エイリアス名（キーストア内での識別名）
     * @param password キーのパスワード（秘密鍵の保護用パスワード）
     */
    @SneakyThrows
    public void addKeyToKeystore(KeyStore keyStore, X509Certificate cert, RSAPrivateKey privateKey, String alias, String password) {
        // パスワード保護オブジェクトを作成（文字配列に変換して使用）
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password.toCharArray());
        // 証明書チェーンを作成（この場合は単一の証明書）
        Certificate[] certificateChain = {cert};
        // 秘密鍵エントリとしてキーストアに登録（秘密鍵 + 証明書チェーン + パスワード保護）
        keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
    }

    /**
     * 空のJKSキーストアを作成します
     * 
     * JKS（Java KeyStore）形式の新しいキーストアインスタンスを作成し、
     * 空のパスワードで初期化します。この初期化は必須で、後続の操作を可能にします。
     * 
     * @return 初期化された空のキーストア
     */
    @SneakyThrows
    public KeyStore createEmptyKeystore() {
        // JKS形式のキーストアインスタンスを取得
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // 空のキーストアとして初期化（nullデータ、空パスワード）
        keyStore.load(null, "".toCharArray());
        return keyStore;
    }

    /**
     * 指定された場所からX.509証明書を読み込みます
     * 
     * リソースローダーを使用して証明書ファイルを読み込み、
     * X.509形式の証明書オブジェクトとして解析します。
     * 
     * @param certLocation 証明書ファイルの場所（クラスパスまたはファイルパス）
     * @return 読み込まれたX.509証明書
     */
    @SneakyThrows
    public X509Certificate loadCert(String certLocation) {
        // X.509証明書を処理するためのファクトリを取得
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        // 指定された場所からリソースを取得
        Resource certRes = resourceLoader.getResource(certLocation);
        // 証明書ファイルを読み込んでX.509証明書オブジェクトを生成
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certRes.getInputStream());
        return cert;
    }

    /**
     * 指定された場所からRSA秘密鍵を読み込みます
     * 
     * PKCS#8形式でエンコードされた秘密鍵ファイルを読み込み、
     * RSAPrivateKeyオブジェクトとして復元します。
     * 秘密鍵ファイルは事前にPKCS#8形式に変換されている必要があります。
     * 
     * @param privateKeyLocation 秘密鍵ファイルの場所（通常は.derファイル）
     * @return 読み込まれたRSA秘密鍵
     */
    @SneakyThrows
    public RSAPrivateKey loadPrivateKey(String privateKeyLocation) {
        // 指定された場所からリソースを取得
        Resource keyRes = resourceLoader.getResource(privateKeyLocation);
        // ファイルの内容をバイト配列として読み込み
        byte[] keyBytes = StreamUtils.copyToByteArray(keyRes.getInputStream());
        // PKCS#8形式のキースペックを作成
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        // RSA用のキーファクトリを取得
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // キースペックから秘密鍵オブジェクトを生成
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * リソースローダーを設定します
     * 
     * 外部からカスタムのリソースローダーを設定する場合に使用します。
     * テスト環境や特殊な設定での証明書・鍵の読み込みに活用できます。
     * 
     * @param resourceLoader 新しいリソースローダー
     */
    public void setResourceLoader(DefaultResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }
}
