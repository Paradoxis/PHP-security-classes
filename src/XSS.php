<?php

/**
 * Namespace
 * @copyright copyright (c) 2014 - 2015 Paradoxis
 */
namespace Paradoxis\Security;

/**
 * XSS protection class
 *
 * XSS is a method in which an attacker is able to run arbitrary JavaScript
 * on a victim's browser with which they are able to steal sessions or
 * make crafted requests to a page, and in the worst case run a browser exploit.
 *
 * This class fixes this vulnerability by sanitizing input given to it
 * and also avoiding undefined variable keys.
 * Usage of the XSRF class is highly advised to protect against XSS.
 * 
 * @package XSS
 * @version 2.0.0
 * @author  paradoxis <luke@paradoxis.nl>
 * @since   2014-12-07
 * @uses    Singleton design pattern
 * @see     https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
 */
class XSS {

	/**
	 * Force singleton pattern
	 */
	private function __construct() {}
	private function __clone() {}

	/**
	 * Get sanitized $_POST value by key
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getPostValue($key, $default = '') {
		return (isset($_POST[$key])) ? self::escape($_POST[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized $_GET value by key
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getGetValue($key, $default = '') {
		return (isset($_GET[$key])) ? self::escape($_GET[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized $_REQUEST value by key
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getRequestValue($key, $default = '') {
		return (isset($_REQUEST[$key])) ? self::escape($_REQUEST[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized $_COOKIE value by key
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getCookieValue($key, $default = '') {
		return (isset($_COOKIE[$key])) ? self::escape($_COOKIE[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized $_SERVER value by key
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getServerValue($key, $default = '') {
		return (isset($_SERVER[$key])) ? self::escape($_SERVER[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized array value by key
	 * @param  array  $array       
	 * @param  string $key       
	 * @param  string $default   
	 * @return string             
	 */
	public static function getArrayValue(array $array, $key, $default = '') {
		return (isset($array[$key])) ? self::escape($array[$key]) : self::escape($default);
	}


	/**
	 * Get sanitized object value by key
	 * @param  object $object
	 * @param  string $key
	 * @param  string $default
	 * @return string
	 */
	public static function getObjectValue($object, $key, $default = '') {
		return (isset($object->$key)) ? self::escape($object->$key) : self::escape($default);
	}


	/**
	 * Sanitize a string
	 * @param  string $string
	 * @return string
	 */
	public static function escape($string) {
		return htmlspecialchars($string);
	}


	/**
	 * Validates and escapes a given URL
	 * @param  string $url  
	 * @param  string $default 
	 * @return string          
	 */
	public static function escapeURL($url, $default = null) {
		if(filter_var($url, FILTER_VALIDATE_URL)) {
			return self::escape($url);
		} else {
			if ($default === null) {
				return 'http://'.self::escape($url);
			} else {
				return self::escape($default);
			}
		}
	}
}
