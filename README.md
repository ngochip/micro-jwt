# micro-jwt
jwt for Yii2

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for the [Yii framework 2.0](http://www.yiiframework.com) (requires PHP 5.5+).
It includes basic HTTP authentication support.

## Installation

Package is available on [Packagist](https://packagist.org/packages/ngochip/micro-jwt),
you can install it using [Composer](http://getcomposer.org).

```shell
composer require ngochip/micro-jwt
```

### Dependencies

- PHP 5.5+
- OpenSSL Extension
- [sizeg/yii2-jwt](https://github.com/sizeg/yii2-jwt)
- [yiisoft/yii2-redis](https://github.com/yiisoft/yii2-redis)

## Basic usage
1. Create RSA key:
```shell
openssl genrsa -des3 -out private.pem 2048

Enter pass phrase for private.pem: [YOUR_PASSPARSE]
Verifying - Enter pass phrase for private.pem:[YOUR_PASSPARSE]
```
Export the RSA Public Key to a File
```shell
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
Exports the Private Key to PEM File
```shell
openssl rsa -in private.pem -out private_unencrypted.pem -outform PEM
```

2.Add `jwt` component to your configuration file,


In Authorization server:

```php
'jwt' => [
      'class' => 'ngochip\jwt\Jwt',
      'privateKey'  => __DIR__.'/../certificate/private.pem', //private key for sign (only setup in authorization server)
      'publicKey'   => __DIR__.'/../certificate/public.pem', //public key for verify in client.
      'passparse'   => '1234', //pass parse private key
      'ttl'       => 60 * 60, //time to live for token
      'ttl_refresh'   => 60 * 90, //time to live for refreshToken
      'redis_config'  => [
        'host'  => '127.0.0.1', // blacklist server address (redis server)
        'port'    => 6379, //redis port
        'database'  => 10,
        'password'  => NULL //password for AUTH redis server
      ]
  ],
```

In Client (other server)

```php
'jwt' => [
      'class' => 'ngochip\jwt\Jwt',
      'publicKey'   => __DIR__.'/../certificate/public.pem', //public key for verify in client.
      'ttl'       => 60 * 60, //time to live for token
      'ttl_refresh'   => 60 * 90, //time to live for refreshToken
      'issuer'        => 'http://auth.domain.com/api/', //Auth Server Address.
      'redis_config'  => [
        'host'  => '127.0.0.1', // blacklist server address (redis server)
        'port'    => 6379, //redis port
        'database'  => 10,
        'password'  => NULL //password for AUTH redis server
      ]
  ],
```


### Creating (in Authorization server)

Just use the builder to create a new JWT/JWS tokens:

```php
$userInfo = [
  'id' => 1,
  'username' => 'admin',
  'email' => 'admin@domain.com',
  'roles' => ['create_post','delete_user']
];
$token = Yii::$app->jwt->getToken($userInfo); //create token
Yii::$app->jwt->setToken($token); //assign Token
$newToken = Yii::$app->jwt->refreshToken(); //refresh token when expried
```
### Use in other server (public key only)
```php
Yii::$app->jwt->getTokenFromHeader(); //get token from Header and set to Object;
Yii::$app->jwt->verify(); //verify token, return bool;
Yii::$app->jwt->getInfo(); //get all info in tokenKey (not verify, only get from token). should be call after verified.
Yii::$app->jwt->getInfo('exp'); //extract claim from token, will return expiry time;
Yii::$app->jwt->getHeader(); //get all header in token.

```

### Verifying

We can easily validate if the token is valid (using the previous token as example):

```php
Yii::$app->jwt->getTokenFromHeader(); //get token from Header Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9....
Yii::$app->jwt->verify(); //verify token, return true if verify success;

```
