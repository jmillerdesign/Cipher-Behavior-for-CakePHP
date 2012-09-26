<?php
App::uses('Security', 'Utility');

/**
 * Cipher Behavior for encrypting/decrypting fields
 *
 * For use with CakePHP
 *
 * @author J. Miller j@jmillerdesign.com
 */
class CipherBehavior extends ModelBehavior {

/**
 * Default settings
 *
 * @var array
 *      - fields array Fields to cipher.								DEFAULT: none
 *      - autoDecrypt boolean Decrypt ciphered value automatically.		DEFAULT: true
 *      - key string Key to encrypt with.								DEFAULT: Security.salt
 *      - cipher string Cipher method to use. (cake|mcrypt|auto)		DEFAULT: auto
 */
	var $_defaults = array(
		'fields' => array(),
		'autoDecrypt' => true,
		'key' => '',
		'cipher' => 'auto'
	);

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

		// Use security salt as default key value
		// Trim to 24 characters for mcrypt
		$this->_defaults['key'] = substr(Configure::read('Security.salt'), 0, 24);

		// Merge config settings with defaults
		$this->settings[$model->name] = array_merge($this->_defaults, $config);

		// Set valid values for config settings
		$this->settings[$model->name]['fields'] = (array) $this->settings[$model->name]['fields'];
		$this->settings[$model->name]['autoDecrypt'] = (boolean) $this->settings[$model->name]['autoDecrypt'];
		$this->settings[$model->name]['cipher'] = $this->_cipherMethod($model->name);
	}

/**
 * Encrypt data on save
 *
 * @param mixed $model Current model
 * @return boolean True to save data
 */
	function beforeSave(&$model) {
		if (!array_key_exists($model->name, $this->settings)) {
			// This model does not use this behavior
			return true;
		}

		// Encrypt each field
		foreach ($this->settings[$model->name]['fields'] as $field) {
			if (!empty($model->data[$model->name][$field])) {
				// Encrypt value
				$model->data[$model->name][$field] = $this->encrypt($model->data[$model->name][$field], $this->settings[$model->name]);
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
		if (!$results || !array_key_exists('fields', $this->settings[$model->name])) {
			// No fields to decrypt
			return $results;
		}

		if ($primary && $this->settings[$model->name]['autoDecrypt']) {
			// Process all results
			foreach ($results as &$result) {
				if (!array_key_exists($model->name, $result)) {
					// Result does not have this model
					continue;
				}

				foreach ($result[$model->name] as $field => &$value) {
					if (in_array($field, $this->settings[$model->name]['fields'])) {
						$value = $this->decrypt($value, $this->settings[$model->name]);
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

		return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($settings['key']), $value, MCRYPT_MODE_CBC, md5(md5($settings['key']))));
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

		return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($settings['key']), base64_decode($value), MCRYPT_MODE_CBC, md5(md5($settings['key']))), "\0");
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
 * @param string $modelName Name of current model
 * @return string (mcrypt|cake) Chosen cipher method
 */
	private function _cipherMethod($modelName) {
		if ($this->settings[$modelName]['cipher'] == 'auto') {
			if (function_exists('mcrypt_module_open')) {
				return 'mcrypt';
			}
		}

		if ($this->settings[$modelName]['cipher'] == 'mcrypt') {
			return 'mcrypt';
		}

		return 'cake';
	}

}
