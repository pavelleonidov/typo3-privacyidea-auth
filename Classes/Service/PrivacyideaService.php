<?php
namespace PavelLeonidov\PrivacyideaAuth\Service;

/***************************************************************
 *
 *  Copyright notice
 *
 *  (c) 2015 Cornelius Kölbel <cornelius.koelbel@netknights.it>, NetKnights GmbH
 *  (c) 2018 Pavel Leonidov <info@pavel-leonidov.de>
 *
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\DebugUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Service "privacyIDEA authentication" for the "privacyidea_auth" extension. This
 * service will authenticate a user against your own hosted privacyIDEA
 * authentication backend. This is done by issuing a POST REST Request to
 * <service>/validate/check with the username and the password.
 * The password may consist of Password and OTP.
 * This way you can authenticate many different TYPO3 instances against one
 * privacyIDEA system.
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 * @author Pavel Leonidov <info@pavel-leonidov.de>
 * @package TYPO3
 * @subpackage tx_privacyidea
 */


class PrivacyideaService extends \TYPO3\CMS\Sv\AbstractAuthenticationService {

	/**
	 * Standard extension key for the service
	 * The extension key.
	 *
	 * @var string
	 */
	public $extKey = 'privacyidea';

	/**
	 * Standard prefix id for the service
	 * Same as class name
	 *
	 * @var string
	 */
	public $prefixId = 'tx_privacyideaauth_service';

	/**
	 * @var \TYPO3\CMS\Core\Log\LogManager
	 */
	protected $logger = NULL;

	/**
	 * @var array
	 */
	protected $config = [];

	/**
	 * Constructor for this class
	 *
	 */
	public function __construct($config = NULL) {
		$this->config = $config;
		$this->logger = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);

		if(!$config) {
			$this->initializeConfiguration();
		}
	}

	/**
	 * @param string $username
	 * @param string $password
	 * @return bool
	 */
	public function checkOtp($username, $password) {
		$curl_instance = curl_init();
		$url = $this->config['privacyIDEAURL'] . '/validate/check';
		$this->logger->info("authenticating against $url");
		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_POST, TRUE);
		$poststring =
			'user=' . urlencode($username) . '&' .
			'pass=' . urlencode($password) . '&' .
			'realm=' . urlencode($this->config['privacyIDEARealm']);
		$this->logger->debug("using the poststring $poststring");


		curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $poststring);
		curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
		curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
		if ($this->config['privacyIDEAsslcheck']) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 1);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
		}
		$response = curl_exec($curl_instance);
		$this->logger->debug($response);
		$header_size = curl_getinfo($curl_instance,CURLINFO_HEADER_SIZE);
		$body = json_decode(substr( $response, $header_size ));



		$status = TRUE;
		$value = TRUE;

		try {
			$status = $body->result->status;
			$value = $body->result->value;
			$res = $value;
		} catch (\Exception $e) {
			$this->logger->error($e);
			$res = FALSE;
		}
		return $res;
	}

	/**
	 * @param string $username
	 * @param string $password
	 * @return bool
	 */
	public function enrollToken($username, $password) {

		$token = $this->authenticateAdminAndGetToken();

		if($token) {
			$curl_instance = curl_init();
			$url = $this->config['privacyIDEAURL'] . '/token/init';
			$this->logger->info("authenticating against $url");
			curl_setopt($curl_instance, CURLOPT_URL, $url);
			curl_setopt($curl_instance, CURLOPT_POST, TRUE);
			$poststring =
				'user=' . urlencode($username) . '&' .
				'email=' . urlencode($username) . '&' .
				'pin=' . urlencode($password) . '&' .
				'realm=' . urlencode($this->config['privacyIDEARealm']) . '&' .
				'genkey=true&hashlib=sha256&dynamic_email=true&otplen=6&type=email';
			$this->logger->debug("using the poststring $poststring");


			curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $poststring);
			curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
			curl_setopt($curl_instance, CURLOPT_HTTPHEADER, ['Authorization: ' . $token]);
			curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
			if ($this->config['privacyIDEAsslcheck']) {
				curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
				curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 1);
			} else {
				curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
				curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
			}
			$response = curl_exec($curl_instance);
			$this->logger->debug($response);
			$header_size = curl_getinfo($curl_instance,CURLINFO_HEADER_SIZE);
			$body = json_decode(substr( $response, $header_size ));


			$status = TRUE;
			$value = TRUE;

			try {
				$status = $body->result->status;
				$value = $body->result->value;
				$res = $value;
			} catch (\Exception $e) {
				$this->logger->error($e);
				$res = FALSE;
			}
			return $res;
		} else {
			return false;
		}

	}

	/**
	 * @return string
	 */
	public function authenticateAdminAndGetToken() {
		$curl_instance = curl_init();
		$url = $this->config['privacyIDEAURL'] . '/auth';
		$this->logger->info("authenticating against $url");
		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_POST, TRUE);
		$poststring =
			'username=admin&' .
			'password=rc2433';
		$this->logger->debug("using the poststring $poststring");

		curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $poststring);
		curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
		curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
		if ($this->config['privacyIDEAsslcheck']) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 1);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
		}
		$response = curl_exec($curl_instance);
		$this->logger->debug($response);
		$header_size = curl_getinfo($curl_instance,CURLINFO_HEADER_SIZE);
		$body = json_decode(substr( $response, $header_size ));

		$token = $body->result->value->token;

		try {
			$status = $body->result->status;
			$value = $body->result->value;
			$res = $token;
		} catch (\Exception $e) {
			$this->logger->error($e);
			$res = "";
		}
		return $res;
	}

	/**
	 * Authenticates the user against privacyIDEA backend
	 *
	 * Will return one of following authentication status codes:
	 *  - 0 - authentication failure
	 *  - 100 - just go on. User is not authenticated but there is still no reason to stop
	 *  - 200 - the service was able to authenticate the user
	 *
	 * @param array $user Array containing the userdata
	 * @return int authentication statuscode, one of 0, 100 and 200
	 */
	public function authUser(array $user) {

		if($this->isOutsideExcludeRange()) {
			$username = $user['username'];
			$password = $user['password'];
			// Enroll email token and initial challenge trigger
			$this->enrollToken($username, $password);
			$authResult = $this->checkOtp($username, $password);
		}
		// always return default authentication method
		return 100;
	}

	protected function initializeConfiguration() {

		$this->logger = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);

		$available = FALSE;
		$extConf = unserialize ($GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['privacyidea_auth']);

		if (isset($extConf['privacyIDEABackend']) && $extConf['privacyIDEABackend'] == 'allUsers' && TYPO3_MODE == 'BE') {
			$available = TRUE;
			$this->config['privacyIDEABackend'] = 'allUsers';
		} elseif (isset($extConf['privacyIDEABackend']) && $extConf['privacyIDEABackend'] == 'adminOnly' && TYPO3_MODE == 'BE') {
			$this->logger->info("Authenticating with privacyIDEA at the Backend (Admin Users)");
			$this->config['privacyIDEABackend'] = 'adminOnly';
			$available = TRUE;
		} elseif (isset($extConf['privacyIDEAFrontend']) && (bool)$extConf['privacyIDEAFrontend'] && TYPO3_MODE == 'FE') {
			$this->logger->info("Authenticating with privacyIDEA at the Frontend");
			$this->config['privacyIDEAFrontend'] = true;
			$available = TRUE;
		} else {
			$this->logger->warning("privacyIDEA Service deactivated.");
		}

		$this->config['privacyIDEARealm'] = $extConf["privacyIDEARealm"];
		$this->config["privacyIDEAsslcheck"] = $extConf["privacyIDEACertCheck"];
		$this->config["privacyIDEAURL"] = $extConf["privacyIDEAURL"];
		$this->config["privacyIDEAAdmin"] = $extConf["privacyIDEAAdmin"];
		$this->config["privacyIDEAPassword"] = $extConf["privacyIDEAPassword"];
		if($extConf['excludeIpAddresses']) {
			$this->config["excludeIpAddresses"] = GeneralUtility::trimExplode(',', $extConf['excludeIpAddresses']);
		}

		return $available;
	}

	/**
	 * Check whether the user is already authenticated
	 *
	 * @return boolean FALSE if the user is already authenticated
	 */
	protected function isOutsideExcludeRange()
	{
		if($this->config['excludeIpAddresses']) {
			return !in_array($_SERVER['REMOTE_ADDR'], $this->config['excludeIpAddresses']);
		}
		return true;
	}
}

?>