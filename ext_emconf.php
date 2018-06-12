<?php

$EM_CONF[$_EXTKEY] = array(
	'title' => 'privacyidea_auth',
	'description' => 'Two-Factor-Authentication against a running privacyIDEA service',
	'category' => 'services',
	'author' => 'Pavel Leonidov',
	'author_email' => 'info@pavel-leonidov.de',
	'state' => 'beta',
	'internal' => '',
	'uploadfolder' => '0',
	'createDirs' => '',
	'clearCacheOnLoad' => 0,
	'version' => '1.0.0',
	'constraints' => array(
		'depends' => array(
			'typo3' => '7.6.0-8.7.99',
		),
		'conflicts' => array(
		),
		'suggests' => array(
		),
	),
);

?>