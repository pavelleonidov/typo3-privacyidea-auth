<?php
namespace PavelLeonidov\PrivacyideaAuth\Service;

/*******************************************************************
 *  Copyright notice
 *
 *  (c) 2018 Pavel Leonidov <pavel.leonidov@mosaiq.com>, MOSAIQ GmbH
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




use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class ConfigurationService implements SingletonInterface {
	
	
	public function getExtConfiguration() {
		$available = FALSE;
		$extConf = unserialize ($GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['privacyidea_auth']);

		if (isset($extConf['privacyIDEABackend']) && $extConf['privacyIDEABackend'] == 'allUsers' && TYPO3_MODE == 'BE') {
			$available = TRUE;
			$config['privacyIDEABackend'] = 'allUsers';
		} elseif (isset($extConf['privacyIDEABackend']) && $extConf['privacyIDEABackend'] == 'adminOnly' && TYPO3_MODE == 'BE') {
			$config['privacyIDEABackend'] = 'adminOnly';
			$available = TRUE;
		} elseif (isset($extConf['privacyIDEAFrontend']) && (bool)$extConf['privacyIDEAFrontend'] && TYPO3_MODE == 'FE') {
			$config['privacyIDEAFrontend'] = true;
			$available = TRUE;
		}

		$config['privacyIDEARealm'] = $extConf["privacyIDEARealm"];
		$config["privacyIDEAsslcheck"] = $extConf["privacyIDEACertCheck"];
		$config["privacyIDEAURL"] = $extConf["privacyIDEAURL"];
		$config["privacyIDEAAdmin"] = $extConf["privacyIDEAAdmin"];
		$config["privacyIDEAPassword"] = $extConf["privacyIDEAPassword"];
		$config["privacyIDEAPassthru"] = $extConf["privacyIDEAPassword"];
		if($extConf['excludeIpAddresses']) {
			$config["excludeIpAddresses"] = GeneralUtility::trimExplode(',', $extConf['excludeIpAddresses']);
		}

		$config["available"] = $available;

		return $config;

	}
}

?>