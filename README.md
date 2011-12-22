# Cipher Behavior for CakePHP 1.3

## Overview

This behavior handles encrypting and decrypting fields, to store information securely in the database. It uses either *mcrypt* or CakePHP's built-in *Security::cipher*.

### Installation

1. Save cipher.php into app/models/behaviors/
2. In the model that has the fields to encrypt, add Cipher to the $actsAs array, along with the settings to use.

		var $actsAs = array(
			'Cipher' => array(
				'fields' => array('password')
			)
		);

### Settings

- fields (array): Fields to cipher. Default: no fields
- autoDecrypt (boolean): Decrypt ciphered fields automatically. Default: true
- key (string): Key to encrypt with. Default: Security.salt
- cipher (string): Cipher method to use (cake OR mcrypt OR auto). Default: auto

[https://github.com/jmillerdesign](https://github.com/jmillerdesign)