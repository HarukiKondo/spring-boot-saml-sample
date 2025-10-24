package com.maclebtec.security.saml.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

/**
 * Web Security設定クラス
 * 
 * このクラスは、Spring SecurityでSAML認証を有効にするための
 * セキュリティ設定を行います。SAML関連のフィルターチェーンの構築、
 * 認証エンドポイントの設定、アクセス制御の定義を担当します。
 * 
 * 主な設定内容：
 * - SAMLフィルターチェーンの構築（ログイン、ログアウト、メタデータ等）
 * - 認証が必要なパスとパブリックパスの定義
 * - SAML認証エントリーポイントの設定
 * - HTTPセキュリティ設定（CSRF無効化、Basic認証無効化等）
 * - メソッドレベルセキュリティの有効化
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /** SAMLログアウト開始フィルター */
    @Autowired
    private SAMLLogoutFilter samlLogoutFilter;

    /** SAMLログアウト処理フィルター（IdPからのレスポンス処理用） */
    @Autowired
    private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;

    /** メタデータ表示フィルター（SPメタデータをブラウザで表示） */
    @Autowired
    private MetadataDisplayFilter metadataDisplayFilter;

    /** メタデータ生成フィルター（SPメタデータの動的生成） */
    @Autowired
    private MetadataGeneratorFilter metadataGeneratorFilter;

    /** SAML Web SSO処理フィルター（標準的なSAML認証レスポンス処理） */
    @Autowired
    private SAMLProcessingFilter samlWebSSOProcessingFilter;

    /** SAML Web SSO HoK処理フィルター（Holder of Key認証処理） */
    @Autowired
    private SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter;

    /** SAMLエントリーポイント（未認証時のIdPリダイレクト処理） */
    @Autowired
    private SAMLEntryPoint samlEntryPoint;

    /** SAML IdP検出フィルター（複数IdP選択画面の処理） */
    @Autowired
    private SAMLDiscovery samlIDPDiscovery;

    /** 認証マネージャー（SAML認証プロバイダーを含む） */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * WebSecurity初期化処理
     * 
     * Spring Securityの初期化時に呼び出されるメソッドです。
     * 現在は親クラスのデフォルト処理のみを実行しています。
     * 
     * @param web WebSecurityオブジェクト
     * @throws Exception 初期化エラー
     */
    @Override
    public void init(WebSecurity web) throws Exception {
        super.init(web);
    }

    /**
     * SAMLフィルターチェーンプロキシを設定します
     * 
     * SAML認証に関連する各種エンドポイント（/saml/*）に対して、
     * 適切なフィルターを適用するためのフィルターチェーンを構築します。
     * 
     * 設定されるエンドポイント：
     * - /saml/login/** : SAML認証開始（IdPリダイレクト）
     * - /saml/logout/** : SAMLログアウト開始
     * - /saml/metadata/** : SPメタデータ表示
     * - /saml/SSO/** : SAML認証レスポンス処理
     * - /saml/SSOHoK/** : HoK認証レスポンス処理
     * - /saml/SingleLogout/** : SAMLログアウトレスポンス処理
     * - /saml/discovery/** : IdP選択処理
     * 
     * @return SAMLフィルターチェーンプロキシ
     * @throws Exception フィルター設定エラー
     */
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        
        // SAML認証開始エンドポイント - ユーザーをIdPにリダイレクト
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint));
        
        // SAMLログアウト開始エンドポイント - SLO（Single Logout）プロセス開始
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter));
        
        // SPメタデータ表示エンドポイント - IdPがSP情報を取得する際に使用
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter));
        
        // SAML認証レスポンス処理エンドポイント - IdPからのSAMLレスポンスを処理
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter));
        
        // HoK認証レスポンス処理エンドポイント - Holder of Key認証レスポンスを処理
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
                samlWebSSOHoKProcessingFilter));
        
        // SAMLログアウトレスポンス処理エンドポイント - IdPからのログアウトレスポンスを処理
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter));
        
        // IdP検出・選択エンドポイント - 複数IdP環境でのIdP選択処理
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
                samlIDPDiscovery));
        
        return new FilterChainProxy(chains);
    }

    /**
     * HTTPセキュリティ設定を行います
     * 
     * Spring SecurityのHTTPセキュリティ設定を行い、SAML認証に適した
     * セキュリティ設定を構築します。
     * 
     * 主な設定内容：
     * - SAML専用セキュリティコンテキストの設定
     * - Basic認証の無効化（SAML認証を使用するため）
     * - CSRF保護の無効化（SAML POST バインディング対応のため）
     * - SAMLエントリーポイントの設定
     * - SAMLフィルターチェーンの組み込み
     * - パス別アクセス制御の設定
     * 
     * @param http HTTPセキュリティ設定オブジェクト
     * @throws Exception 設定エラー
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // SAML専用のセキュリティコンテキストリポジトリを設定
        // 通常のSpring Securityとは別のコンテキストキーを使用
        HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
        securityContextRepository.setSpringSecurityContextKey("SPRING_SECURITY_CONTEXT_SAML");
        http
                .securityContext().securityContextRepository(securityContextRepository);
        
        // Basic認証を無効化（SAML認証を使用するため不要）
        http
                .httpBasic().disable();
        
        // CSRF保護を無効化（SAMLのPOSTバインディングと競合するため）
        http
                .csrf().disable();
        
        // 未認証時の例外処理 - SAMLエントリーポイントにリダイレクト
        http
                .exceptionHandling()
                .authenticationEntryPoint(samlEntryPoint);
        
        // SAMLフィルターチェーンをSpring Securityフィルターチェーンに組み込み
        http
                // メタデータ生成フィルターを最初に配置（SPメタデータの動的生成用）
                .addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class)
                // SAMLフィルターをBasic認証フィルターの後に配置
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
                // SAMLフィルターをCSRFフィルターの前に配置（CSRFが無効でも順序を明確化）
                .addFilterBefore(samlFilter(), CsrfFilter.class);
        
        // URL別アクセス制御の設定
        http
                .authorizeRequests()
                // パブリックアクセス可能なパス（認証不要）
                .antMatchers("/",              // ルートページ
                        "/error",               // エラーページ
                        "/saml/**",             // SAML関連エンドポイント全般
                        "/idpselection")        // IdP選択画面
                .permitAll()
                // その他のすべてのリクエストは認証が必要
                .anyRequest().authenticated();

        // 標準のログアウト機能を無効化（SAMLログアウトを使用するため）
        http
                .logout()
                .disable();
    }

    /**
     * 認証マネージャーを提供します
     * 
     * Spring Securityが認証処理で使用する認証マネージャーを返します。
     * このマネージャーには、SAMLConfigで設定されたSAML認証プロバイダーが
     * 含まれており、SAML認証レスポンスの処理を担当します。
     * 
     * @return SAML認証プロバイダーを含む認証マネージャー
     * @throws Exception 認証マネージャー取得エラー
     */
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return authenticationManager;
    }
}
