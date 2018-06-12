<?php
defined('TYPO3_MODE') or die();



\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService($_EXTKEY,
	  'auth',
	  'tx_privacyideaauth_service',
      [
            'title' => 'Authentication against privacyIDEA for FE/BE',
            'description' => 'authenticate user by using OTP with privacyIDEA',
            'subtype' => 'authUserFE,authUserBE',
            'available' => TRUE,
            'priority' => 80,
            'quality' => 80,
            'os' => '',
            'exec' => '',
            'className' => PavelLeonidov\PrivacyideaAuth\Service\PrivacyideaService::class
      ]
);

// Register hook for user auth, use post user lookup as next possible hook AFTER user authentication
$TYPO3_CONF_VARS['SC_OPTIONS']['t3lib/class.t3lib_userauth.php']['postUserLookUp'][] = PavelLeonidov\PrivacyideaAuth\Hooks\UserAuthHook::class . '->postUserLookUp';


?>
