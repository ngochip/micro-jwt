<?php

namespace ngochip\jwt;

use Yii;
use yii\base\Component;
use yii\base\InvalidParamException;
use yii\redis\Connection as Redis;
use sizeg\jwt\Jwt as SizeGJWT;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com>
 * @since 1.0.0-a
 */
class Jwt extends Component
{
	public $privateKey;
	public $publicKey;
	public $passparse;
	public $ttl;
	public $ttl_refresh;
	public $redis_config;

	private $token;
	private $signer;
	private $keychain;
	private $sizeGJWT;

	CONST PRE_BLACKLIST_KEY = "auth:blackList:";

	public function __construct(){
		$this->signer = new Sha256();
    	$this->keychain = new Keychain();
    	$this->sizeGJWT = new SizeGJWT();
    	$this->_initRedis();
	}

	/*
	* tạo mới token
	*/
	public function getToken($info = null, $uid = null){
		if($info == null){
			return (string) $this->token;
		}

		$this->token = $this->_getToken($info, $uid);
		return (string) $this->token;
	}

	/*
	*
	*/
	public function setToken($token){
		$this->token = $this->sizeGJWT->getParser()->parse((string) $token);
	}
	/*
	*
	* verify lại token
	*/
	public function verify(){
		$verify = $this->token->verify($this->signer, $this->keychain->getPublicKey('file://'.$this->publicKey));
		return $verify;
	}

	/*
	* tạo token mới khi hết hạn
	*/
	public function refreshToken(){
		$expire 		= $this->getInfo("exp");
		$iat 			= $this->getInfo('iat'); //time that the token was issue
		$ttl 			= $this->redis_config['ttl'];
		$ttlRefresh 	= $this->redis_config['ttl'];
		$remain 		= time() - $expire;
		$remainRefreshTime = time() - ($iat + $ttlRefresh);
		$info 			= $this->getInfo();

		if($remainRefreshTime <= 0){
			return false; //hết hạn refresh token
		}
		if($remain > 0){
			$this->_addToBlackList();
		}
		return $this->getToken($info);
	}
	//get claim from token
	public function getInfo($claimName = 'info'){
		$this->token->getClaims();
		return $this->token->getClaim($claimName);
	}

	public function getHeader($headerName){
		$this->token->getHeaders();
		return $this->token->getHeader($headerName);
	}

	/*
	* private function
	*/
	private function _getToken($info, $uid = null){
    	$builder = $this->sizeGJWT->getBuilder()->setIssuer(Yii::$app->homeUrl)
        // ->setAudience('http://example.org')
        ->setIssuedAt(time())
        ->setNotBefore(time())
        ->setExpiration(time() + $this->ttl)
        ->set('info', $info);
        if($uid == null){
        	$builder->setId('uid', $uid);
        }
        $builder->sign(
        	$this->signer,
        	$this->keychain->getPrivateKey('file://'.$this->privateKey, $this->passparse)
       	);
       	$token = $builder->getToken();
       	return $token;
	}

	private function _initRedis(){
		$this->Redis = new Redis();
		$config = $this->redis_config;
		$this->Redis->hostname = isset($config['host']) ? $config['host'] : "localhost";
		$this->Redis->port = isset($config['port']) ? $config['port'] : 6379;
		$this->Redis->password = isset($config['password']) ? $config['password'] : null;
		$this->Redis->database = isset($config['database']) ? $config['database'] : 0;
	}

	private function _getRedisKeyName($key){
		return self::PRE_BLACKLIST_KEY.md5($key);
	}
	private function _addToBlackList(){
		$expire = $this->getInfo("exp");
		$tokenString = $this->getToken();
		$keyName = $this->_getRedisKeyName($tokenString);
		$remain = time() - $expire;

		return $this->Redis->executeCommand("SET", [$keyName, '1','NX','EX',$remain]);
	}
	private function _inBlackList(){
		$tokenString = $this->getToken();
		$keyName = $this->_getRedisKeyName($tokenString);
		return $this->Redis->executeCommand("EXISTS", [$keyName]);
	}

}

