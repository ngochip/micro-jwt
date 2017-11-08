<?php

namespace ngochip\jwt;

use Yii;
use yii\base\Component;
use yii\base\InvalidParamException;
use sizeg\jwt\Jwt as SizeGJWT;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com>
 * @since 1.0.0-a
 */
class Jwt extends Component
{
	public $ttl;
	public $ttl_refresh;

	public function getToken($info){
		echo "xxxx";
	}
}