<?php

namespace ngochip\jwt;

use Yii;
use yii\base\Component;
use yii\base\InvalidParamException;
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
	private $token;
	private $signer;
	private $keychain;
	private $sizeGJWT;

	public function __construct(){
		$this->signer = new Sha256();
    	$this->keychain = new Keychain();
    	$this->sizeGJWT = new SizeGJWT();
	}

	/*
	* tạo mới token
	*/
	public function getToken($info, $uid = null){
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
	*
	*/

	public function getInfo($claimName = 'info'){
		$this->token->getClaims();
		return $this->token->getClaim($claimName);
	}

	/*
	*
	*/

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

}