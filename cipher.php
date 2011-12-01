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
 */
	var $default = array(
		'fields' => array('password'),
		'autoDecrypt' => true,
		'key' => ''
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

		if (isset($config['key'])) {
			$this->config[$model->name]['key'] = (string) $config['key'];
		} else {
			$this->config[$model->name]['key'] = Configure::read('Security.salt');
		}

		if (isset($config['fields'])) {
			$this->config[$model->name]['fields'] = (array) $config['fields'];
		}

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
		return Security::cipher($value, $settings['key']);
	}

/**
 * Decrypt value
 *
 * @param string $value Value to decrypt
 * @param array $settings Config settings
 * @return string Decrypted value
 */
	public function decrypt($value, $settings) {
		return Security::cipher($value, $settings['key']);
	}

/**
 * Check if array is associative (keys are not numeric, incrementing sequentially from zero).
 *
 * @param array $array The array to check
 * @return boolean True if array is associative
 */
	private function isAssoc($array) {
		return (is_array($array) && (count($array) == 0 || 0 !== count(array_diff_key($array, array_keys(array_keys($array))))));
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
}