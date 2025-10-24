## Spring Bootを使用したSpring Security SAMLサンプル ##
このサンプルは、従来の`spring-security-saml`ライブラリを使用して、Spring BootアプリにSP（サービスプロバイダ）機能を追加し、さまざまなIdP（IDプロバイダ）に対して認証できるようにします。
このモジュールの主な目的は、これらすべての複雑さを内部で処理するSpring Boot用の`spring-boot-security-saml`プラグインと比較して、Spring Security SAMLを使用するために必要な広範な設定を公開することです。

## 動かし方

### ビルド

```bash
mvn clean install  
```

以下のようになればOK!

```bash
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  28.153 s
[INFO] Finished at: 2025-10-24T02:30:38Z
[INFO] ------------------------------------------------------------------------
```

### ローカルでサーバー起動

```bash
java -jar target/spring-security-saml-sample-1.1.0-SNAPSHOT.jar
```

### 自己署名証明書を作成するコマンド 

- *RSAキーを作成するコマンド*: `openssl genrsa -out localhost.key 2048`
- *cerファイルを生成するコマンド*: `openssl req -new -x509 -key localhost.key -out localhost.cer -days 365`
- *derファイルを作成するコマンド*: `openssl pkcs8 -topk8 -nocrypt -in localhost.key -outform DER -out localhost.key.der`

### 利用可能なIdP ####

- [SSO Circle](http://www.ssocircle.com/en/)
- [OneLogin](https://www.onelogin.com/)
- [Ping One Cloud](https://www.pingidentity.com/en/products/pingone.html)
- [OKTA](https://www.okta.com)

### 認証情報 ###

以下の認証情報を使用してください：

- *SSO Circle:* [SSO Circle](http://www.ssocircle.com/en/)に登録し、その認証情報を使用してアプリケーションにログインします。
- *OneLogin:* [OneLogin](https://www.onelogin.com/)に登録し、その認証情報を使用してアプリケーションにログインします。
- *Ping One:* [Ping One Cloud](https://www.pingidentity.com/en/products/pingone.html)に登録し、その認証情報を使用してアプリケーションにログインします。
- *OKTA:* [OKTA](https://www.okta.com)に登録し、その認証情報を使用してアプリケーションにログインします。

### OneLoginの設定 ###

このサンプルアプリケーションでOneLoginを使用するには、次の手順を実行する必要があります：
- [OneLogin開発者アカウント](https://www.onelogin.com/developer-signup)を作成します。
  - フリートライアルは30日間有効
- SAMLテストコネクタ（IdP）を追加します。
- OneLoginアプリケーションを以下のように設定します：
  - *RelayState:* ここには何でも使用できます。
  - *Audience:* localhost-demo
  - *Recipient:* http://localhost:8080/saml/SSO
  - *ACS (Consumer) URL Validator:* ^http://localhost:8080/saml/SSO.*$
  - *ACS (Consumer) URL:* http://localhost:8080/saml/SSO
  - *Single Logout URL:* http://localhost:8080/saml/SingleLogout
  - *Parameters:* firstName、lastNameなどの追加パラメータを追加できます。
- SSOタブで：
  - *X.509 Certificate:* 既存のX.509 PEM証明書をコピーして`idp-onelogin.xml`（ds:X509Certificate）に貼り付けます。
  - *SAML Signature algorythm:* SHA-256を使用しますが、SHA-1も引き続き機能します。
  - *Issuer URL:* `idp-onelogin.xml`のentityIDをこの値に置き換えます。
  - *SAML 2.0 Endpoint (HTTP):* `idp-onelogin.xml`のHTTP-RedirectおよびHTTP-POSTバインディングの場所をこの値に置き換えます。
  - *SLO Endpoint (HTTP):* `idp-onelogin.xml`のHTTP-Redirectバインディングの場所をこの値に置き換えます。

### Oktaログイン設定 ###

このサンプルアプリケーションでOktaを使用するには、次の手順を実行する必要があります：
- [Okta開発者アカウント](https://www.okta.com)を作成します。
- サンプルSAMLコネクタの詳細を追加します。
- Oktaアプリケーションを以下のように設定します：
  - *Single Sign On URL* `http://localhost:8081/saml/SSO`
  - *Recipient URL* `http://localhost:8081/saml/SSO`
  - *Destination URL* `http://localhost:8081/saml/SSO`
  - *Audience Restriction* `http://localhost:8081/saml/metadata`
  - *Default Relay State* `任意の値を提供できます`
  - *Name ID Format* `Unspecified`
  - *Response* `Signed`
  - *Assertion Signature* `Signed`
  - *Signature Algorithm* `RSA_SHA256`
  - *Digest Algorithm* SHA256
  - *Assertion Encryption* Unencrypted
  - *Single Logout URL* `http://localhost:8081/saml/logout`
  - *SP Issuer* `http://localhost:8081/saml/metadata`
  - *Signature Certificate* X509 PEM証明書である`localhost.cert`をアップロードします。
  - *Authentication context class* `X509 certificate`
  - *Honor Force Authentication* `No`
  - *SAML Issuer ID* `デフォルト値`
  - *Parameters* 表示用にいくつかのパラメータを設定します。
- 最終的に生成されたメタデータファイルを`idp-okta.xml`にコピー＆ペーストする必要があります。
