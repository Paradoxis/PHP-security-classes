<?php

/**
 * Namespace
 * @copyright copyright (c) 2014 Paradoxis
 */
namespace \Paradoxis\Security;

/**
 * Download protection class
 *
 * This class is designed to securely allow users to download a file without
 * the risk of full path disclosure, relative path traversal or source code / sensitive file
 * exposure.
 *
 * It instantly disables the possibility of header injection and null byte poison 
 * attacks when sanitizing user inputted strings.
 * 
 * @package Security
 * @version 1.1.0
 * @author  paradoxis <luke@paradoxis.nl>
 * @since   2014-12-07
 * @uses    Factory design pattern
 * @see     https://www.owasp.org/index.php/Full_Path_Disclosure
 * @see     https://www.owasp.org/index.php/Relative_Path_Traversal
 * @see     https://www.owasp.org/index.php/Information_Leakage
 * @see     https://www.owasp.org/index.php/CRLF_Injection
 */
class Download {

	/**
	 * File set by the user (possibly malicious)
	 * @var string
	 */
	private $file;

	/**
	 * Set path by the programmer
	 * @var string
	 */
	private $path = '';

	/**
	 * Allowed extensions
	 * @var array (numeric)
	 */
	private $extensions = array('pdf', 'jpg', 'jpeg', 'png', 'gif', 'zip');

	/**
	 * Whitelisted files
	 * @var array
	 */
	private $whitelist = array();

	/**
	 * All errors thrown by the script
	 * @var array
	 */
	private $errors = array();


	/**
	 * Constructor function
	 * @param string $file (User provided filename) 
	 * @param string $path (Developer provided path, DO NOT PUT USER DATA IN HERE, IT WILL NOT GET SANITIZED!!)      
	 * @param array  $extensions
	 */
	public function __construct($file, $path = null, array $extensions = null, array $whitelist = null) {

		// Set filename
		$this->file = $file;

		// Set path
		if ($path) {
			if (substr(strlen($path), strlen($path) - 1, $path) !== DIRECTORY_SEPARATOR) {
				$this->path = $path . DIRECTORY_SEPARATOR;
			} else {
				$this->path = $path;
			}
		}

		// Set extension whitelist
		if ($extensions) {
			$this->extensions = $extensions;
		}

		// Set filename whitelist.
		if ($whitelist) {
			$this->whitelist = $whitelist;
		}
	}


	/**
	 * Validate whether the file provided is allowed
	 * @return boolean
	 */
	public function validate() {

		// Check if the extension is valid
		if ($this->extensionAllowed( $this->getFileName(false) ) === false) {
			$this->errors[] = "Illegal file extension";
			return false;
		}

		// Check if the given filename is in the whitelist
		if (empty($this->whitelist) === false) {
			if ($this->fileInWhiteList( $this->getFileName(false) )) {
				$this->errors[] = "Illegal file name";
				return false;
			}
		}

		// Check if the file exists
		if ($this->fileExists( $this->getFileName(true) ) === false) {
			$this->errors[] = "File does not exist";
			return false;
		} else {
			return true;
		}
	}


	/**
	 * Validate if a given extension is valid or not
	 * @param  string $file
	 * @return boolean 
	 */
	private function extensionAllowed($file) {
		return in_array(strtolower(end(explode('.', $file))), array_map('strtolower', $this->extensions));
	}


	/**
	 * Check if a given filename is in the whitelisted file array (or string)
	 * @param  string $file
	 * @return boolean
	 */
	private function fileInWhiteList($file) {
		return in_array($file, $this->whitelist);
	}


	/**
	 * Check if a file exists or not (and is readable)
	 * @param  string $file 
	 * @return boolean
	 */
	private function fileExists($file) {
		return (file_exists($file) && is_readable($file));
	}


	/**
	 * Return file string by using the path + sanitized filename 
	 * (with the most overkill sensitization function ever)
	 * 
	 * @param  boolean $fullPath
	 * @return string
	 */
	private function getFileName($fullPath = false) {
		if ($fullPath) {
			return $this->path . $this->sanitize( $this->file );
		} else {
			return $this->sanitize( $this->file );
		}
	}


	/**
	 * Sanitize given string for:
	 * - Path traversal
	 * - Null-byte poison
	 * - Header injection
	 * 
	 * @param  string $string
	 * @return string
	 */
	private function sanitize($string) {
		return str_replace(array(
 				
				// Hexadecimal path traversal characters (../ | ..\)
				"\x2E\x2E\x2F",
				"\x2E\x2E\x5C",
				"\x2E\x2F",
				"\x2E\x5C",
				"\x2F",
				"\x5C",

				// Header injection characters (hex): \r \n
				"\x0D\x0A",
				"\x0D",
				"\x0A",

				// Null byte poison string \0
				"\x00"
			), 

			// Replace with an empty string :)
			'',

			// Apply to:
			$string
		);
	}


	/**
	 * Trigger the download function.
	 * Fails when there are any errors.
	 * @return boolean
	 */
	public function download() {
		if ($this->hasErrors() === false) {
			header('Content-Disposition: attachment; size=' . filesize( $this->getFileName(true) )); 
			header('Content-type: application/force-download');
			header('Content-Transfer-Encoding: binary');  
			header('Content-Disposition: attachment; filename="'. $this->getFileName(false) .'"');
			readfile( $this->getFileName(true) );
			return true;
		} else {
			return false;
		}
	}


	/**
	 * Check if there are any errors
	 * @return boolean 
	 */
	public function hasErrors() {
		return (empty($this->errors) === false);
	}


	/**
	 * Return all thrown errors
	 * @return array
	 */
	public function getErrors() {
		return $this->errors;
	}
}
