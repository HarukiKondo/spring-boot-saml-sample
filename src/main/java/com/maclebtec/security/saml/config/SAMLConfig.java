package com.maclebtec.security.saml.config;

import com.google.common.collect.ImmutableMap;
import com.maclebtec.security.saml.spring.security.SAMLUserDetailsServiceImpl;
import com.maclebtec.security.saml.certificate.KeystoreFactory;
import com.maclebtec.security.saml.spring.SpringResourceWrapperOpenSAMLResource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Timer;
import java.util.stream.Stream;

/**
 * SAML認証に関する設定ファイル
 * 
 * このクラスは、Spring Security SAMLを使用したSSO（シングルサインオン）認証の
 * 設定を行うための設定クラスです。
 * 
 * 主な機能：
 * - SAML認証プロバイダーの設定
 * - IDPメタデータの自動読み込み
 * - SAML処理フィルターの設定
 * - キーストア・証明書管理の設定
 * - ログイン・ログアウト処理の設定
 * 
 * このクラスにより、複数のIdentity Provider（IdP）に対する
 * SAML認証が可能になります。
 */
@AutoConfigureBefore(WebSecurityConfig.class)
@Configuration
@Slf4j
public class SAMLConfig {

    @Autowired
    private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

    /**
     * SAML認証プロバイダーを設定します
     * 
     * SAML認証レスポンスを処理し、ユーザー詳細情報を取得するための
     * 認証プロバイダーを作成します。
     * 
     * @return SAML認証プロバイダー
     */
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        // ユーザー詳細サービスを設定（SAML属性からユーザー情報を取得）
        provider.setUserDetails(samlUserDetailsServiceImpl);
        // プリンシパルを文字列として強制しない（オブジェクト形式を維持）
        provider.setForcePrincipalAsString(false);
        return provider;
    }

    /**
     * 認証マネージャーを設定します
     * 
     * SAML認証プロバイダーを使用する認証マネージャーを作成します。
     * Spring Securityの認証処理の中核となるコンポーネントです。
     * 
     * @return 認証マネージャー
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(samlAuthenticationProvider()));
    }

    /**
     * XMLパーサープールを設定します
     * 
     * SAMLメッセージの解析に使用するXMLパーサーのプールを作成します。
     * パフォーマンス向上のため、パーサーインスタンスを再利用します。
     * 
     * @return 静的基本パーサープール
     */
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    /**
     * SAMLプロセッサーを設定します
     * 
     * 各種SAMLバインディング（HTTP-Redirect、HTTP-POST、Artifact等）を
     * 処理するためのプロセッサーを作成します。複数の通信方式に対応しています。
     * 
     * @return SAMLプロセッサー実装
     */
    @Bean
    public SAMLProcessorImpl processor() {
        // マルチスレッド対応のHTTPクライアントを作成
        HttpClient httpClient = new HttpClient(new MultiThreadedHttpConnectionManager());
        // SAML Artifactの解決処理を設定
        ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
        HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(parserPool());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));

        // HTMLフォーム生成用のVelocityエンジンを取得
        VelocityEngine velocityEngine = VelocityFactory.getEngine();
        
        // 各種SAMLバインディングを設定
        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(new HTTPRedirectDeflateBinding(parserPool()));           // HTTP-Redirectバインディング
        bindings.add(new HTTPPostBinding(parserPool(), velocityEngine));       // HTTP-POSTバインディング
        bindings.add(new HTTPArtifactBinding(parserPool(), velocityEngine, artifactResolutionProfile)); // HTTP-Artifactバインディング
        bindings.add(new HTTPSOAP11Binding(parserPool()));                     // SOAP 1.1バインディング
        bindings.add(new HTTPPAOS11Binding(parserPool()));                     // PAOS 1.1バインディング
        
        return new SAMLProcessorImpl(bindings);
    }

    /**
     * ログアウト成功ハンドラーを設定します
     * 
     * ログアウト処理が正常に完了した際のリダイレクト先を設定します。
     * デフォルトではルートページ（"/"）にリダイレクトします。
     * 
     * @return ログアウト成功ハンドラー
     */
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
        handler.setDefaultTargetUrl("/");
        return handler;
    }

    /**
     * セキュリティコンテキストログアウトハンドラーを設定します
     * 
     * ログアウト時にセッションの無効化と認証情報のクリアを行います。
     * セキュリティ上重要な処理を担当します。
     * 
     * @return セキュリティコンテキストログアウトハンドラー
     */
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        // HTTPセッションを無効化
        handler.setInvalidateHttpSession(true);
        // 認証情報をクリア
        handler.setClearAuthentication(true);
        return handler;
    }

    /**
     * SAMLログアウトフィルターを設定します
     * 
     * SAML Single Logout（SLO）プロセスを開始するためのフィルターです。
     * ローカルログアウトとグローバルログアウトの両方を処理します。
     * 
     * @return SAMLログアウトフィルター
     */
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        SAMLLogoutFilter filter = new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
        return filter;
    }

    /**
     * SAMLログアウト処理フィルターを設定します
     * 
     * IdPからのログアウトレスポンスを処理するためのフィルターです。
     * SLOプロセスの完了処理を担当します。
     * 
     * @return SAMLログアウト処理フィルター
     */
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        SAMLLogoutProcessingFilter filter = new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
        return filter;
    }

    /**
     * メタデータ生成フィルターを設定します
     * 
     * Service Provider（SP）のメタデータを動的に生成するフィルターです。
     * IdPがSPの設定情報を取得する際に使用されます。
     * 
     * @param metadataGenerator メタデータ生成器
     * @return メタデータ生成フィルター
     */
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter(MetadataGenerator metadataGenerator) {
        return new MetadataGeneratorFilter(metadataGenerator);
    }

    /**
     * メタデータ表示フィルターを設定します
     * 
     * SPのメタデータをブラウザで表示するためのフィルターです。
     * 通常は/saml/metadataエンドポイントで利用されます。
     * 
     * @return メタデータ表示フィルター
     * @throws Exception 設定エラー
     */
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() throws Exception {
        MetadataDisplayFilter filter = new MetadataDisplayFilter();
        return filter;
    }

    /**
     * IdPメタデータローダーを設定します
     * 
     * クラスパス内のidp-*.xmlファイルを自動的に読み込み、
     * 各IdPのメタデータプロバイダーとしてSpringコンテナに登録します。
     * これにより、複数のIdPに対する認証が可能になります。
     * 
     * @return Beanファクトリポストプロセッサー
     */
    @Bean
    BeanFactoryPostProcessor idpMetadataLoader() {
        return beanFactory -> {
            // クラスパス内のIdPメタデータファイルを検索するためのリゾルバー
            PathMatchingResourcePatternResolver metadataFilesResolver = new PathMatchingResourcePatternResolver();
            try {
                // "classpath:/saml/idp-*.xml"パターンでファイルを検索
                Resource[] idpMetadataFiles = metadataFilesResolver.getResources("classpath:/saml/idp-*.xml");
                Stream.of(idpMetadataFiles).forEach(idpMetadataFile -> {
                    try {
                        // メタデータの定期更新用タイマー（デーモンスレッド）
                        Timer refreshTimer = new Timer(true);
                        ResourceBackedMetadataProvider delegate = null;
                        // Springリソースラッパーを使用してメタデータプロバイダーを作成
                        delegate = new ResourceBackedMetadataProvider(refreshTimer, new SpringResourceWrapperOpenSAMLResource(idpMetadataFile));
                        delegate.setParserPool(parserPool());
                        
                        // 拡張メタデータの設定をクローン
                        ExtendedMetadata extendedMetadata = extendedMetadata().clone();
                        ExtendedMetadataDelegate provider = new ExtendedMetadataDelegate(delegate, extendedMetadata);
                        
                        // メタデータの検証設定
                        provider.setMetadataTrustCheck(true);        // 信頼性チェックを有効化
                        provider.setMetadataRequireSignature(false); // 署名検証は無効化（開発環境用）
                        
                        // ファイル名からIdP名を抽出（例: idp-okta.xml → okta）
                        String idpFileName = idpMetadataFile.getFilename();
                        String idpName = idpFileName.substring(idpFileName.lastIndexOf("idp-") + 4, idpFileName.lastIndexOf(".xml"));
                        extendedMetadata.setAlias(idpName);
                        
                        // IdPプロバイダーをSpringコンテナにシングルトンとして登録
                        beanFactory.registerSingleton(idpName, provider);
                        log.info("Loaded Idp Metadata bean {}: {}", idpName, idpMetadataFile);
                    } catch (Exception e) {
                        throw new IllegalStateException("Unable to initialize IDP Metadata", e);
                    }
                });
            } catch (Exception e) {
                throw new IllegalStateException("Unable to initialize IDP Metadata", e);
            }
        };
    }


    /**
     * 拡張メタデータを設定します
     * 
     * SAML認証の詳細設定を行うための拡張メタデータを作成します。
     * IdP選択画面の表示やセキュリティ設定などを制御します。
     * 
     * @return 拡張メタデータ
     */
    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata metadata = new ExtendedMetadata();
        // IdP選択画面をユーザーに表示するかどうか（複数IdP対応時にtrue）
        metadata.setIdpDiscoveryEnabled(true);
        // ログアウトリクエストの署名を必須とする
        metadata.setRequireLogoutRequestSigned(true);
        // ログアウトレスポンスの署名を必須とするかどうか（コメントアウト）
        //metadata.setRequireLogoutResponseSigned(true);
        // SPメタデータに署名を付与しない（開発環境用設定）
        metadata.setSignMetadata(false);
        return metadata;
    }

    /**
     * メタデータ生成器を設定します
     * 
     * Service Provider（SP）のメタデータを生成するための設定を行います。
     * Entity IDやキー管理など、SPの基本情報を定義します。
     * 
     * @param keyManager キー管理器（証明書・秘密鍵管理用）
     * @return メタデータ生成器
     */
    @Bean
    public MetadataGenerator metadataGenerator(KeyManager keyManager) {
        MetadataGenerator generator = new MetadataGenerator();
        // SP（この アプリケーション）のEntity IDを設定
        generator.setEntityId("http://localhost:8081/saml/metadata");
        // 拡張メタデータの設定を適用
        generator.setExtendedMetadata(extendedMetadata());
        // IdP Discovery拡張を含めない
        generator.setIncludeDiscoveryExtension(false);
        // 署名・暗号化用のキー管理器を設定
        generator.setKeyManager(keyManager);
        return generator;
    }

    /**
     * SAML Web SSO処理フィルターを設定します
     * 
     * IdPからのSAMLレスポンスを処理し、ユーザー認証を行うフィルターです。
     * 認証成功・失敗時の処理も設定します。
     * 
     * @return SAML処理フィルター
     * @throws Exception 設定エラー
     */
    @Bean(name = "samlWebSSOProcessingFilter")
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        // 認証マネージャーを設定
        filter.setAuthenticationManager(authenticationManager());
        // 認証成功時のリダイレクト処理を設定
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        // 認証失敗時のエラー処理を設定
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return filter;
    }

    /**
     * SAML Web SSO HoK（Holder of Key）処理フィルターを設定します
     * 
     * HoK（Holder of Key）バインディングによるSAML認証を処理するフィルターです。
     * 通常のWeb SSO処理に加えて、鍵の所有証明も行います。
     * 
     * @return SAML Web SSO HoK処理フィルター
     * @throws Exception 設定エラー
     */
    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter filter = new SAMLWebSSOHoKProcessingFilter();
        // 認証成功時のリダイレクト処理を設定
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        // 認証マネージャーを設定
        filter.setAuthenticationManager(authenticationManager());
        // 認証失敗時のエラー処理を設定
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return filter;
    }

    /**
     * 認証成功時のリダイレクトハンドラーを設定します
     * 
     * 認証成功後に、ユーザーが元々アクセスしようとしていたページまたは
     * デフォルトページにリダイレクトします。
     * 
     * @return 認証成功リダイレクトハンドラー
     */
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        // 認証成功後のデフォルトリダイレクト先を設定
        handler.setDefaultTargetUrl("/home");
        return handler;
    }

    /**
     * 認証失敗時のハンドラーを設定します
     * 
     * 認証失敗時のエラーページ遷移を制御します。
     * リダイレクトまたはフォワードの選択も可能です。
     * 
     * @return 認証失敗ハンドラー
     */
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler();
        // フォワードではなくリダイレクトを使用
        handler.setUseForward(false);
        // 認証失敗時のデフォルトリダイレクト先を設定
        handler.setDefaultFailureUrl("/error");
        return handler;
    }

    /**
     * SAML IdP検出フィルターを設定します
     * 
     * 複数のIdPが利用可能な場合に、ユーザーにIdP選択画面を表示するための
     * フィルターです。IdP選択後、適切なIdPにリダイレクトします。
     * 
     * @return SAML IdP検出フィルター
     */
    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery filter = new SAMLDiscovery();
        // IdP選択画面のパスを設定
        filter.setIdpSelectionPath("/idpselection");
        return filter;
    }

    /**
     * SAMLエントリーポイントを設定します
     * 
     * 未認証ユーザーがアクセスした際に、SAML認証プロセスを開始するための
     * エントリーポイントです。IdPへのリダイレクト処理を担当します。
     * 
     * @return SAMLエントリーポイント
     */
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        // Web SSOプロファイルのオプション設定
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        // スコーピング情報を含めない（シンプルな認証リクエスト用）
        options.setIncludeScoping(false);
        
        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
        // デフォルトプロファイルオプションを設定
        entryPoint.setDefaultProfileOptions(options);
        return entryPoint;
    }

    /**
     * キーストアファクトリーを設定します
     * 
     * 証明書と秘密鍵からキーストアを作成するためのファクトリーです。
     * Springのリソースローダーを使用してファイルアクセスを行います。
     * 
     * @param resourceLoader Springリソースローダー
     * @return キーストアファクトリー
     */
    @Bean
    public KeystoreFactory keystoreFactory(ResourceLoader resourceLoader) {
        return new KeystoreFactory(resourceLoader);
    }

    /**
     * キーマネージャーを設定します
     * 
     * SAML署名・暗号化で使用する証明書と秘密鍵を管理するマネージャーです。
     * ローカルホスト用の証明書を読み込み、JKSキーマネージャーとして設定します。
     * 
     * @param keystoreFactory キーストア作成ファクトリー
     * @return JKSキーマネージャー
     */
    @Bean
    public KeyManager keyManager(KeystoreFactory keystoreFactory) {
        // クラスパスから証明書と秘密鍵を読み込んでキーストアを作成
        KeyStore keystore = keystoreFactory.loadKeystore("classpath:/saml/localhost.cert",
                "classpath:/saml/localhost.key.der", "localhost", "");
        // JKSキーマネージャーを作成（エイリアス"localhost"、空パスワード、デフォルトキー"localhost"）
        return new JKSKeyManager(keystore, ImmutableMap.of("localhost", ""), "localhost");
    }

    /**
     * TLSプロトコル設定を行います
     * 
     * HTTPS通信時のTLS設定を行うコンフィギュレーターです。
     * キーマネージャーを設定して、クライアント証明書認証などに対応します。
     * 
     * @param keyManager キーマネージャー
     * @return TLSプロトコルコンフィギュレーター
     */
    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer(KeyManager keyManager) {
        TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
        // クライアント証明書認証用のキーマネージャーを設定
        configurer.setKeyManager(keyManager);
        return configurer;
    }

}
