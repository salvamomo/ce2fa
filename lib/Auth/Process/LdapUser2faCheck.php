<?php

/**
 * Filter to manipulate request in order to enforce the user to pass 2fa.
 *
 * @author Salvador Molina <salva.momo@gmail.com>
 * @package SimpleSAMLphp
 */
class sspmod_simplesamlphp_2fa_check_Auth_Process_LdapUser2faCheck extends sspmod_ldap_Auth_Process_BaseFilter
{

	/**
	 * Initialize this filter.
	 *
	 * @param array $config Configuration information about this filter.
	 * @param mixed $reserved For future use.
	 */
	public function __construct($config, $reserved)
	{
		parent::__construct($config, $reserved);
	}


	/**
	 * Add attributes from an LDAP server.
	 *
	 * @param array &$request The current request
	 */
	public function process(&$request)
	{
//		assert(is_array($request));
//		assert(array_key_exists('Attributes', $request));
//
//		$attributes =& $request['Attributes'];
	}

}
