<?php
/**
 * Cipher Behavior for encrypting/decrypting fields
 *
 * @package cake
 * @author J. Miller j@jmillerdesign.com
 */
class CipherBehavior extends ModelBehavior {

/**
 * Default settings
 *
 * @var array
 *      - fields array Fields to cipher.								DEFAULT: password
 *      - autoDecrypt boolean Decrypt ciphered value automatically.		DEFAULT: true
 *      - key string Key to encrypt with.								DEFAULT: Security.salt
 *      - cipher string Cipher method to use. (cake|mcrypt|auto)		DEFAULT: auto
 */
	var $default = array(
		'fields' => array('password'),
		'autoDecrypt' => true,
		'key' => '',
		'cipher' => 'auto'
	);

/**
 * Config settings. A merge of default settings and specified model settings
 *
 * @var array
 */
	var $config = array();

/**
 * Behavior initialization
 *
 * @param mixed $model Current model
 * @param array $config Config settings
 * @return void
 */
	function setup(&$model, $config = array()) {
		if (!$this->_cipherSeedValidates()) {
			trigger_error('Security.cipherSeed is invalid', E_USER_ERROR);
		}

		$this->config[$model->name] = $this->default;

		// Cipher method
		if (isset($config['cipher'])) {
			$this->config[$model->name]['cipher'] = $config['cipher'];
		}
		$this->config[$model->name]['cipher'] = $this->_cipherMethod();

		// Key
		if (isset($config['key'])) {
			$this->config[$model->name]['key'] = $config['key'];
		} else if ($this->config[$model->name]['cipher'] == 'mcrypt') {
			$this->config[$model->name]['key'] = substr(Configure::read('Security.salt'), 0, 24);
		} else {
			$this->config[$model->name]['key'] = Configure::read('Security.salt');
		}

		// Fields
		if (isset($config['fields'])) {
			$this->config[$model->name]['fields'] = (array) $config['fields'];
		}

		// Auto-Decrypt
		if (isset($config['autoDecrypt'])) {
			$this->config[$model->name]['autoDecrypt'] = (bool) $config['autoDecrypt'];
		}
	}

/**
 * Encrypt data on save
 *
 * @param mixed $model Current model
 * @return boolean True to save data
 */
	function beforeSave(&$model) {
		if (!isset($this->config[$model->name])) {
			// This model does not use this behavior
			return true;
		}

		// Encrypt each field
		foreach ($this->config[$model->name]['fields'] as $field) {
			if (!empty($model->data[$model->name][$field])) {
				// Encrypt value
				$model->data[$model->name][$field] = $this->encrypt($model->data[$model->name][$field], $this->config[$model->name]);
			}
		}

		return true;
	}

/**
 * Decrypt data on find
 *
 * @param mixed $model Current model
 * @param mixed $results The results of the find operation
 * @param boolean $primary Whether this model is being queried directly (vs. being queried as an association)
 * @return mixed Result of the find operation
 */
	function afterFind(&$model, $results, $primary = false) {
		if (!$results || !isset($this->config[$model->name]['fields'])) {
			// No fields to decrypt
			return $results;
		}

		if ($primary && $this->config[$model->name]['autoDecrypt']) {
			// Process all results
			foreach ($results as &$result) {
				if (!isset($result[$model->name])) {
					// Result does not have this model
					continue;
				}

				foreach ($result[$model->name] as $field => &$value) {
					if (in_array($field, $this->config[$model->name]['fields'])) {
						$value = $this->decrypt($value, $this->config[$model->name]);
					}
				}
			}
		}

		return $results;
	}

/**
 * Encrypt value
 *
 * @param string $value Value to encrypt
 * @param array $settings Config settings
 * @return string Encrypted value
 */
	public function encrypt($value, $settings) {
		if ($settings['cipher'] == 'cake') {
			return Security::cipher($value, $settings['key']);
		}

		$iv = 'fYfhHeDm';	// 8 bit IV
		$bitCheck = 8;		// bit amount for diff algor.

		$textNum = str_split($value, $bitCheck);
		$textNum = $bitCheck - strlen($textNum[count($textNum) - 1]);

		for ($i = 0; $i < $textNum; $i++) {
			$value = $value . chr($textNum);
		}

		$cipher = mcrypt_module_open(MCRYPT_TRIPLEDES, '', 'cbc', '');
		mcrypt_generic_init($cipher, $settings['key'], $iv);
		$decrypted = mcrypt_generic($cipher, $value);
		mcrypt_generic_deinit($cipher);
		return base64_encode($decrypted);
	}

/**
 * Decrypt value
 *
 * @param string $value Value to decrypt
 * @param array $settings Config settings
 * @return string Decrypted value
 */
	public function decrypt($value, $settings) {
		if ($settings['cipher'] == 'cake') {
			return Security::cipher($value, $settings['key']);
		}

		$iv = 'fYfhHeDm';	// 8 bit IV
		$bitCheck = 8;		// bit amount for diff algor.

		$cipher = mcrypt_module_open(MCRYPT_TRIPLEDES, '', 'cbc', '');
		mcrypt_generic_init($cipher, $settings['key'], $iv);
		$decrypted = @mdecrypt_generic($cipher, base64_decode($value));
		mcrypt_generic_deinit($cipher);
		$lastChar = substr($decrypted, -1);
		for ($i = 0; $i < ($bitCheck - 1); $i++) {
		    if (chr($i) == $lastChar) {
		        $decrypted = substr($decrypted, 0, strlen($decrypted) - $i);
		        break;
		    }
		}
		return $this->stripInvalidChars($decrypted);
	}

/**
 * Validate cipher seed
 *
 * @return boolean True if validates
 */
	private function _cipherSeedValidates() {
		$seed = Configure::read('Security.cipherSeed');
		return ($seed && is_numeric($seed));
	}

/**
 * Get chosen cipher method
 *
 * @return string (mcrypt|cake) Chosen cipher method
 */
	private function _cipherMethod() {
		if ($this->config[$model->name]['cipher'] == 'auto') {
			if (function_exists('mcrypt_module_open')) {
				return 'mcrypt';
			}
		}

		if ($this->config[$model->name]['cipher'] == 'mcrypt') {
			return 'mcrypt';
		}

		return 'cake';
	}

/**
 * Strip invalid characters from string
 *
 * @param string $str Original string
 * @return string String with invalid characters removed
 */
	private function stripInvalidChars($str) {
		return preg_replace('/[^(\x20-\x7F)]*/', '', $str);
	}
}
