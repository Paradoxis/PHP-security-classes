<?php

/**
 * Namespace
 * @copyright copyright (c) 2014 Paradoxis
 */
namespace Paradoxis\Security;

/**
 * XSRF protection class
 * 
 * XSRF is a method with which an attacker can make a XMLHttpRequest (ajax)
 * to a specific page to perform certain actions on a web page of another user.
 * This can be done by tricking the user into clicking an XSS link or viewing a malicious web page. (own/external domain)
 *
 * This class fixes this flaw by creating a pseudo-random string that is set within a form and in a session variable.
 * Once a user submits a form with a hidden field the strings are compared and if successful the developer can
 * do whatever they please with the results.
 * 
 * @package Security
 * @version 1.2.0
 * @author  paradoxis <luke@paradoxis.nl>
 * @since   2014-12-10
 * @uses    Factory design pattern
 * @see     https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
 */
class XSRF {

	/**
	 * XSRF session token salt
	 * The token will combine this salt into the new session token
	 * It's advised to change this when using it in production areas
	 * @var string default: 'PRXgydcAyvvCuMzDow2EhzbYlo5CbKrauu3CST7T'
	 */
	const SESSION_TOKEN_SALT = 'PRXgydcAyvvCuMzDow2EhzbYlo5CbKrauu3CST7T';

	/**
	 * XSRF session token length
	 * The token will be sha1 hashed, which are always 40 characters long.
	 * This variable simply ups the randomness of the hash.
	 * @var int default: 15
	 */
	const SESSION_TOKEN_LENGTH = 15;


	/**
	 * XSRF array for all tokens
	 * @var string
	 */
	protected $SESSION_ARRAY_NAME = 'XSRF_TOKENS';

	/**
	 * XSRF session token
	 * @var string
	 */
	protected $SESSION_TOKEN_NAME = 'XSRF_TOKEN';

	/**
	 * XSRF post token
	 * @var string
	 */
	protected $POST_TOKEN_NAME    = 'XSRF_TOKEN';


	/**
	 * Constructor function
	 * @param string $session_key
	 * @param string $post_key
	 * @param string $session_array
	 * @return XSRF
	 */
	public function __construct($session_key = null, $post_key = null, $session_array = null) {
		if ($session_key) {
			$this->SESSION_TOKEN_NAME = $session_key;
		}

		if ($post_key) {
			$this->POST_TOKEN_NAME    = $post_key;
		}

		if ($session_array) {
			$this->SESSION_ARRAY_NAME = $session_array;
 		}

 		if (isset($_SESSION[ $this->SESSION_ARRAY_NAME ]) === false) {
 			$_SESSION[ $this->SESSION_ARRAY_NAME ] = array();
 		}
	}


	/**
	 * Unset current XSRF token
	 * @return boolean
	 */
	public function destroyToken() {
		if(isset($_SESSION[  $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ])) {
			unset($_SESSION[ $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ]);
			return true;
		} else {
			return false;
		}
	}


	/**
	 * Create and set the session token
	 * @return string
	 */
	public function generateToken() {
		return (string) $_SESSION[ $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ] = $this->createToken(); 
	}


	/**
	 * Get current session token
	 * @return string 
	 */
	public function getToken() {
		return (string) $_SESSION[ $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ];
	}


	/**
	 * Check if session and post token match
	 * @return boolean
	 */
	public function tokenIsValid() {
		if ($this->tokenIsSet()) {
			return (
				$_POST[ $this->POST_TOKEN_NAME ] === $_SESSION[ $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ]
			);
		} else {
			return false;
		}
	}


	/**
	 * Check if post and session tokens are both set
	 * @return boolean 
	 */
	public function tokenIsSet() {
		return (
			isset($_POST[ $this->POST_TOKEN_NAME ]) &&
			isset($_SESSION[ $this->SESSION_ARRAY_NAME ][ $this->SESSION_TOKEN_NAME ])
		);
	}


	/**
	 * Create a pseudo random sha1 token
	 * @return string 
	 */
	protected function createToken() {
		$chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:;.,<>?/~!@#$%^&*()_+';
		$token = '';

		for ($i = 0; $i < self::SESSION_TOKEN_LENGTH; $i++) {
			$token .= (string) chr($chars[ mt_rand(0, strlen($chars) - 1) ]);
		}

		return sha1($token . time() . mt_rand() . self::SESSION_TOKEN_SALT);
	}
}
