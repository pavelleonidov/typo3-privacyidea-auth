<?php

namespace PavelLeonidov\PrivacyideaAuth\Hooks;

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

use PavelLeonidov\PrivacyideaAuth\Auth\PrivacyideaAuthenticator;
use PavelLeonidov\PrivacyideaAuth\Service\ConfigurationService;
use Tx\Authenticator\Auth\TokenAuthenticator;
use TYPO3\CMS\Backend\Template\DocumentTemplate;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\DebugUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\PathUtility;
use TYPO3\CMS\Fluid\View\StandaloneView;
use TYPO3\CMS\Lang\LanguageService;

/**
 * Straddles into the normal backend user authentication process to display the 2-factor form.
 */
class UserAuthHook
{
	/**
	 * @var AbstractUserAuthentication
	 */
	protected $user = null;


	/**
	 * @var array
	 */
	protected $config = [];

	/**
	 * @var \TYPO3\CMS\Core\Log\LogManager
	 */
	protected $logger = NULL;

	/**
	 * Check if authentication is needed and validate the token
	 *
	 * @param array $params
	 * @param AbstractUserAuthentication $user
	 *
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	public function postUserLookUp(array $params, AbstractUserAuthentication $user)
	{
		$this->user = $user;
		$this->initializeConfiguration();


		if ($this->canAuthenticate() && $this->needsAuthentication() && $this->isOutsideExcludeRange()) {
			$authenticator = GeneralUtility::makeInstance(PrivacyideaAuthenticator::class, $this->user, $this->config);
			$postTokenCheck = $authenticator->verify(
				$this->user,
				(integer)GeneralUtility::_GP('oneTimeSecret')
			);
			if ($postTokenCheck) {
				$this->setValidTwoFactorInSession();
				$authenticator->revoke($this->user);
			} else {

				$this->showForm(GeneralUtility::_GP('oneTimeSecret'));
			}
		}
	}


	/**
	 * Check for a valid user, enabled two factor authentication and if a secret is set
	 *
	 * @return boolean TRUE if the user exists and can be authenticated
	 */
	protected function canAuthenticate()
	{
		return $this->user instanceof AbstractUserAuthentication
			&& $this->user->user['uid'] > 0;
	}

	/**
	 * Check whether the user is already authenticated
	 *
	 * @return boolean FALSE if the user is already authenticated
	 */
	protected function needsAuthentication()
	{
		$validatedInSession = $this->user->getSessionData('authenticatorIsValidTwoFactor') !== true;
		$isBackendTwoFactorActivated = isset($this->config['privacyIDEABackend']) && in_array($this->config['privacyIDEABackend'], ['allUsers', 'adminOnly']);
		$twoFactorDeactivatedByFile = file_exists(PATH_site . 'deactivateTwoFactor');
		return $validatedInSession && $isBackendTwoFactorActivated && !$twoFactorDeactivatedByFile;
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
	 * Mark the current session as checked
	 *
	 * @return void
	 */
	protected function setValidTwoFactorInSession()
	{
		$this->user->setAndSaveSessionData('authenticatorIsValidTwoFactor', true);
	}

	/**
	 * Render the form and exit execution
	 *
	 * @param string $token Provided (wrong) token
	 */
	protected function showForm($token)
	{
		$this->initializeLanguageService();

		$documentTemplate = $this->getDocumentTemplate();

		$backendExtConf = unserialize($this->getExtConf('backend'));

		if (!empty($backendExtConf['loginBackgroundImage'])) {
			$backgroundImage = $this->getUriForFileName($backendExtConf['loginBackgroundImage']);
			$css = /** @lang CSS */
				'@media (min-width: 768px){
            .typo3-login-carousel-control.right,
            .typo3-login-carousel-control.left,
            .panel-login { border: 0; }
            .typo3-login { background-image: url("' . $backgroundImage . '"); }
            }';
			$documentTemplate->inDocStylesArray[] = $css;
		}

		if (!empty($backendExtConf['loginLogo'])) {
			$logo = $backendExtConf['loginLogo'];
		} else {
			if (!empty($backendExtConf['loginHighlightColor'])) {
				$logo = 'EXT:backend/Resources/Public/Images/typo3_black.svg';
			} else {
				$logo = 'EXT:backend/Resources/Public/Images/typo3_orange.svg';
			}
			$documentTemplate->inDocStylesArray[] = '.typo3-login-logo .typo3-login-image { max-width: 150px; }';
		}
		$logo = $this->getUriForFileName($logo);

		$highlightColor = $backendExtConf['loginHighlightColor'];
		if (!empty($highlightColor)) {
			$documentTemplate->inDocStylesArray[] = /** @lang CSS */
				'.btn-login.tx_authenticator_login_button,
            .btn-login.tx_authenticator_login_button:hover,
            .btn-login.tx_authenticator_login_button:active,
            .btn-login.tx_authenticator_login_button:active:hover,
            .btn-login.tx_authenticator_login_button:focus { background-color: ' . $highlightColor . '; }
            .panel-login .panel-body.tx_authenticator_login_wrap { border-color: ' . $highlightColor . '; }';
		}

		$content = $documentTemplate->startPage('TYPO3 CMS Login: ' . $this->getSiteName());
		$content .= $this->renderLoginForm($token, $logo);
		$content .= $documentTemplate->endPage();

		$this->printContentAndDie($content);
	}

	/**
	 * @param string $content
	 *
	 * @SuppressWarnings(PHPMD.ExitExpression)
	 */
	protected function printContentAndDie($content)
	{
		// throw away any previous rendered/outputted content
		ob_clean();
		// output "our" content
		echo $content;
		// quit immediately to prevent any further rendering
		die();
	}

	/**
	 * @return DocumentTemplate
	 *
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function getDocumentTemplate()
	{
		if (!isset($GLOBALS['TBE_TEMPLATE']) || !($GLOBALS['TBE_TEMPLATE'] instanceof DocumentTemplate)) {
			$GLOBALS['TBE_TEMPLATE'] = GeneralUtility::makeInstance(DocumentTemplate::class);
		}
		return $GLOBALS['TBE_TEMPLATE'];
	}

	/**
	 * @param string $token
	 * @param string $logo
	 * @return string
	 */
	protected function renderLoginForm($token, $logo)
	{
		$view = GeneralUtility::makeInstance(StandaloneView::class);
		$view->setLayoutRootPaths(['EXT:privacyidea_auth/Resources/Private/Layouts']);
		$view->setTemplateRootPaths(['EXT:privacyidea_auth/Resources/Private/Templates']);
		$view->setTemplate('LoginToken');
		$view->assign('token', $token);
		$view->assign('hasLoginError', !empty($token));
		$view->assign('logo', $logo);
		return $view->render();
	}

	/**
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function initializeUserAuthentication()
	{
		if (TYPO3_MODE === 'BE' && isset($GLOBALS['BE_USER'])) {
			$this->user = $GLOBALS['BE_USER'];
		} elseif (TYPO3_MODE === 'FE' && isset($GLOBALS['FE_USER'])) {
			$this->user = $GLOBALS['FE_USER'];
		} else {
			$this->user = null;
		}
	}

	/**
	 * @return mixed
	 *
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function getSiteName()
	{
		return $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename'];
	}

	/**
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function initializeLanguageService()
	{
		// Translation service is initialized too late in bootstrap
		$GLOBALS['LANG'] = GeneralUtility::makeInstance(LanguageService::class);
		$GLOBALS['LANG']->init((TYPO3_MODE === 'BE' && isset($this->user->uc['lang'])) ? $this->user->uc['lang'] : '');
	}

	/**
	 * @param string $extKey
	 * @return string
	 *
	 * @SuppressWarnings(PHPMD.Superglobals)
	 */
	protected function getExtConf($extKey)
	{
		return $GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf'][$extKey];
	}

	/**
	 * COPY
	 * @see \TYPO3\CMS\Backend\Controller\LoginController::getUriForFileName
	 *
	 * @param string $filename
	 * @return string
	 * @internal
	 */
	private function getUriForFileName($filename)
	{
		if (strpos($filename, '://')) {
			return $filename;
		}
		$urlPrefix = '';
		if (strpos($filename, 'EXT:') === 0) {
			$absoluteFilename = GeneralUtility::getFileAbsFileName($filename);
			$filename = '';
			if ($absoluteFilename !== '') {
				$filename = PathUtility::getAbsoluteWebPath($absoluteFilename);
			}
		} elseif (strpos($filename, '/') !== 0) {
			$urlPrefix = GeneralUtility::getIndpEnv('TYPO3_SITE_PATH');
		}
		return $urlPrefix . $filename;
	}

	protected function initializeConfiguration() {

		$this->logger = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(LogManager::class)->getLogger(__CLASS__);

		$configurationService = GeneralUtility::makeInstance(ConfigurationService::class);
		$this->config = $configurationService->getExtConfiguration();
	}
}

?>