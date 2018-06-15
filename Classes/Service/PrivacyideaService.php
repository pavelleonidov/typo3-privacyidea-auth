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
	public $extKey = 'privacyidea_auth';

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

		$postString =
			'user=' . urlencode($username) . '&' .
			'pass=' . urlencode($password) . '&' .
			'realm=' . urlencode($this->config['privacyIDEARealm']);
		$response = $this->sendRequestandGetResult("/validate/check", $postString);

		return $response["result"];
	}

	/**
	 * @param string $username
	 * @param string $email
	 * @param string $password
	 * @return bool
	 */
	public function enrollToken($username, $email, $password) {

		$token = $this->authenticateAdminAndGetToken();
		$res = FALSE;

		if($token) {
			$postString =
				'user=' . urlencode($username) . '&' .
				'email=' . urlencode($email) . '&' .
				'pin=' . urlencode($password) . '&' .
				'realm=' . urlencode($this->config['privacyIDEARealm']) . '&' .
				'genkey=true&hashlib=sha256&dynamic_email=true&otplen=6&type=email';

			$response = $this->sendRequestandGetResult("/token/init", $postString, ['Authorization: ' . $token]);

			$res = $response["result"];

		}
		return $res;
	}

	/**
	 * @return string
	 */
	public function authenticateAdminAndGetToken() {
		$postString = 'username=' . $this->config["privacyIDEAAdmin"] . '&password=' . $this->config["privacyIDEAPassword"];
		$response = $this->sendRequestandGetResult("/auth", $postString);

		$token = "";

		if($response["result"]) {
			$token = $response["body"]->result->value->token;
		}

		return $token;
	}

	/**
	 * Authenticates the user against privacyIDEA backend
	 *
	 * Will return one of following authentication status codes:
	 *  - 0 - authentication failure
	 *  - 100 - proceed with default authentication (will call the postUserLookUp hook)
	 *
	 * @param array $user Array containing the userdata
	 * @return int authentication statuscode, either 0 or 100
	 */
	public function authUser(array $user) {

		if($this->isOutsideExcludeRange() && isset($this->config['privacyIDEABackend']) && in_array($this->config['privacyIDEABackend'], ['allUsers', 'adminOnly'])) {
			$username = $user['username'];
			$password = $user['password'];
			$email = $user['email'];

			// Enroll email token and initial challenge trigger
			$success = $this->enrollToken($username, $email, $password);
			if(!$success) {
				if($this->config["privacyIDEAPassthru"]) {
					return 100;
				} else {
					return 0;
				}
			} else {
				$this->checkOtp($username, $password);
				return 100;
			}
		} else {
			return 100;
		}
	}


	/**
	 * Initialize extConf
	 */
	protected function initializeConfiguration() {

		$this->logger = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);

		$configurationService = GeneralUtility::makeInstance(ConfigurationService::class);
		$this->config = $configurationService->getExtConfiguration();
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

	/**
	 * abstract cURL request method
	 *
	 * @param string $endpoint relative endpoint of the privacyIDEA service
	 * @param string $postString post request string
	 * @param string $header additional header for the reques
	 */
	protected function sendRequestandGetResult($endpoint, $postString, $header = []) {
		$curl_instance = curl_init();
		$url = $this->config['privacyIDEAURL'] . $endpoint;
		$this->logger->info("authenticating against $url");
		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_POST, TRUE);

		$this->logger->debug("using the poststring $postString");

		curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $postString);
		curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
		if(!empty($header)) {
			curl_setopt($curl_instance, CURLOPT_HTTPHEADER, $header);
		}
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
		return [
			"result" => $res,
			"body" => $body
		];
	}
}

?>