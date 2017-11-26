<?php

namespace ngochip\jwt;

use Yii;
use yii\base\Component;
use yii\base\InvalidParamException;
use yii\helpers\BaseUrl as Url;
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
	public $issuer;

	private $token;
	private $signer;
	private $keychain;
	private $sizeGJWT;
	private $redis;

	CONST PRE_BLACKLIST_KEY = "auth:blackList:";
	CONST LOG_CATEGORY		= "ngochip-jwt";

	public function init(){
		parent::init();
		$this->signer = new Sha256();
    	$this->keychain = new Keychain();
    	$this->sizeGJWT = new SizeGJWT();
    	$this->issuer = ($this->issuer === null) ? Url::home(true): $this->issuer;
    	
    	$this->_initRedis();
    	$this->getTokenFromHeader();
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

	public function getTokenFromHeader(){
		$token = Yii::$app->request->getHeaders()->get("Authorization");
		$this->setToken(substr($token,7));
	}
	/*
	*
	*/
	public function setToken($token){
		$tokenString = (string) $token;
		if(count(explode(".", $tokenString)) != 3){
			return false;
		}
		$this->token = $this->sizeGJWT->getParser()->parse((string) $token);
	}
	/*
	*
	* verify lại token
	*/
	public function verify(){
		if(!$this->_validateToken()){
			return false;
		}
		return true;
	}

	/*
	* tạo token mới khi hết hạn
	*/
	public function refreshToken(){
		$expire 		= $this->getInfo("exp");
		$remain 		=  $expire - time();
		$info 			= $this->getInfo();

		if(!$this->_validateRefreshToken()){
			Yii::info("cant not validate token",self::LOG_CATEGORY);
			return false; //hết hạn refresh token
		}

		$this->_addToBlackList();
		return $this->getToken($info);
	}
	//get claim from token
	public function getInfo($claimName = 'info'){
		if(!$this->token){
			return false;
		}
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
    	$builder = $this->sizeGJWT->getBuilder()->setIssuer($this->issuer)
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
	private function _validateToken($time = null){
		if(!$this->token){
			return false;
		}
		if($this->_inBlackList()){
			Yii::info("token in blacklist",self::LOG_CATEGORY);
			return false;
		}
		$data = $this->sizeGJWT->getValidationData();
		$data->setIssuer($this->issuer);

		if($time){
			$data->setCurrentTime($time);
		}

		$validate = $this->token->validate($data);
		$verify = $this->token->verify($this->signer, $this->keychain->getPublicKey('file://'.$this->publicKey));
		if(!$validate || !$verify){
			Yii::info("validate:{$validate}, verify: {$verify}",self::LOG_CATEGORY);
		}
		return ($validate && $verify);
	}
	private function _validateRefreshToken(){
		$expire 		= $this->getInfo("exp");
		$iat 			= $this->getInfo('iat'); //time that the token was issue
		$ttl 			= $this->ttl;
		$ttlRefresh 	= $this->ttl_refresh;
		$time = time() - ($ttlRefresh - $ttl);
		$time = ($time < $iat) ? $iat: $time;
		return $this->_validateToken($time);
	}

	private function _initRedis(){
		$this->redis = new Redis();
		$config = $this->redis_config;
		$this->redis->hostname = isset($config['host']) ? $config['host'] : "localhost";
		$this->redis->port = isset($config['port']) ? $config['port'] : 6379;
		$this->redis->password = isset($config['password']) ? $config['password'] : null;
		$this->redis->database = isset($config['database']) ? $config['database'] : 0;
	}

	private function _getRedisKeyName($key){
		return self::PRE_BLACKLIST_KEY.md5($key);
	}
	private function _addToBlackList(){
		$IssuedAt = $this->getInfo("iat");
		$tokenString = $this->getToken();
		$keyName = $this->_getRedisKeyName($tokenString);
		$refreshExpried = $IssuedAt + $this->ttl_refresh;
		$remain = $refreshExpried - time();
		return $this->redis->executeCommand("SET", [$keyName, '1','NX','EX',$remain]);
	}
	private function _inBlackList(){
		$tokenString = $this->getToken();
		$keyName = $this->_getRedisKeyName($tokenString);
		return $this->redis->executeCommand("EXISTS", [$keyName]);
	}
}

