# Cipher Behavior for CakePHP

## Overview

This plugin behavior handles encrypting and decrypting fields, to store information securely in the database. It uses either *mcrypt* or CakePHP's built-in *Security::cipher*. This version supports CakePHP 2.1.

### Installation

1. Install the plugin as a submodule:

		git submodule add https://github.com/jmillerdesign/Cipher-Behavior-for-CakePHP.git app/Plugin/Cipher
2. Load the plugin in Config/bootstrap.php

		CakePlugin::load('Cipher');
3. In the model(s) that has the fields to encrypt, add Cipher.Cipher to the $actsAs array, along with the settings to use.

		var $actsAs = array(
			'Cipher.Cipher' => array(
				'fields' => array('password')
			)
		);

### Settings

- fields (array): Fields to cipher. Default: no fields
- autoDecrypt (boolean): Decrypt ciphered fields automatically. Default: true
- key (string): Key to encrypt with. Default: Security.salt
- cipher (string): Cipher method to use (cake OR mcrypt OR auto). Default: auto

[http://jmillerdesign.github.com/Cipher-Behavior-for-CakePHP/](http://jmillerdesign.github.com/Cipher-Behavior-for-CakePHP/)
