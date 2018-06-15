<?php

namespace PavelLeonidov\PrivacyideaAuth\Auth;

/*******************************************************************
 *  Copyright notice
 *
 *  (c) 2018 Pavel Leonidov <info@pavel-leonidov.de>
 *
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
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
 ******************************************************************/

use PavelLeonidov\PrivacyideaAuth\Service\PrivacyideaService;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Database\DatabaseConnection;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\DebugUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Creates and verifies the one time token
 */
class PrivacyideaAuthenticator implements SingletonInterface
{

	/**
	 * @var AbstractUserAuthentication
	 */
	protected $user = null;

	/**
	 * User data array from the user object, effectively the database row of the user
	 *
	 * @var array $this ->user->user
	 */
	protected $userData = [];

	/**
	 * @var \PavelLeonidov\PrivacyideaAuth\Service\PrivacyideaService
	 */
	protected $privacyIdeaService = NULL;

	/**
	 * @param AbstractUserAuthentication $user
	 * @param array $config The config params
	 */
	public function __construct($user, $config)
	{
		$this->setUser($user);
		$this->privacyIdeaService = GeneralUtility::makeInstance(PrivacyideaService::class, $config);
	}

	/**
	 * Set the current user context
	 *
	 * @param AbstractUserAuthentication $user
	 * @throws \UnexpectedValueException
	 */
	public function setUser(AbstractUserAuthentication $user)
	{
		$this->user = $user;
		if (is_array($user->user)) {
			$this->userData = $user->user;
		} else {
			throw new \UnexpectedValueException(
				'The user object has not been initialized - the user data is missing.',
				1396181716
			);
		}
	}

	/**
	 * Verifies a token
	 *
	 * @param AbstractUserAuthentication $user the user array
	 * @param integer $token
	 * @return bool
	 */
	public function verify($user, $token)
	{
		if($token) {
			$success = $this->privacyIdeaService->checkOtp($user->user["username"], $user->user['password'] . $token);

		} else {
			$success = false;
		}
		return $success;
	}

	/**
	 * Verifies a token
	 *
	 * @param AbstractUserAuthentication $user the user array
	 * @return bool
	 */
	public function revoke($user)
	{
		return $this->privacyIdeaService->deleteToken($user->user["username"]);
	}

	/**
	 * Returns the instance of the database connection
	 *
	 * @return DatabaseConnection
	 *
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function getDatabaseConnection()
	{
		return $GLOBALS['TYPO3_DB'];
	}


}

?>